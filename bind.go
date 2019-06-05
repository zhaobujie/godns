package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type BindError struct {
	qname, net  string
	nameservers []string
}

func (e BindError) Error() string {
	errmsg := fmt.Sprintf("%s resolv failed on %s (%s)", e.qname, strings.Join(e.nameservers, "; "), e.net)
	return errmsg
}

type BindResp struct {
	msg        *dns.Msg
	nameserver string
	rtt        time.Duration
}

type BindFind struct {
	servers       []string
	domain_server *suffixTreeNode
	config        *BINDServerSettings
}

func NewBindFind(c BINDServerSettings) *BindFind {
	r := &BindFind{
		servers:       []string{},
		domain_server: newSuffixTreeRoot(),
		config:        &c,
	}

	//这里测试阶段只保留一个bind server
	nameserver := net.JoinHostPort(settings.BindServer.Host,
		string(settings.BindServer.Port))
	r.servers = append(r.servers, nameserver)

	return r
}

func (r *BindFind) parseServerListFile(buf *os.File) {
	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if !strings.HasPrefix(line, "server") {
			continue
		}

		sli := strings.Split(line, "=")
		if len(sli) != 2 {
			continue
		}

		line = strings.TrimSpace(sli[1])

		tokens := strings.Split(line, "/")
		switch len(tokens) {
		case 3:
			domain := tokens[1]
			ip := tokens[2]

			if !isDomain(domain) || !isIP(ip) {
				continue
			}
			r.domain_server.sinsert(strings.Split(domain, "."), ip)
		case 1:
			srv_port := strings.Split(line, "#")
			if len(srv_port) > 2 {
				continue
			}

			ip := ""
			if ip = srv_port[0]; !isIP(ip) {
				continue
			}

			port := "53"
			if len(srv_port) == 2 {
				if _, err := strconv.Atoi(srv_port[1]); err != nil {
					continue
				}
				port = srv_port[1]
			}
			r.servers = append(r.servers, net.JoinHostPort(ip, port))
		}
	}

}

func (r *BindFind) ReadServerListFile(path string) {
	files := strings.Split(path, ";")
	for _, file := range files {
		buf, err := os.Open(file)
		if err != nil {
			panic("Can't open " + file)
		}
		defer buf.Close()
		r.parseServerListFile(buf)
	}
}

// 该函数是向配置文件中指定的bind list中进行dns query
// Lookup will ask  nameserver in bind list, starting a new request
// in every second, and return as early as possbile (have an answer).
// It returns an error if no request has succeeded.
func (r *BindFind) Lookup(netType string, req *dns.Msg) (message *dns.Msg, err error) {
	c := &dns.Client{
		Net:          netType,
		ReadTimeout:  r.Timeout(),
		WriteTimeout: r.Timeout(),
	}

	if netType == "udp" && settings.BindServer.SetEDNS0 {
		//原来的实现只有edns0的opt头部
		//req = req.SetEdns0(65535, true)
		//新实现可添加subnet，这只是个示例demonstrate，后续还要判断是否已经是subnet报文
		opt := new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(4096)
		opt.SetDo(true)
		subnet := new(dns.EDNS0_SUBNET)
		subnet.Code = dns.EDNS0SUBNET
		subnet.Family = 1	// 1 for IPv4 source address, 2 for IPv6
		subnet.SourceNetmask = 32	// 32 for IPV4, 128 for IPv6
		subnet.SourceScope = 0
		subnet.Address = net.ParseIP("127.0.0.1").To4()	// for IPv4
		//	// e.Address = net.ParseIP("2001:7b8:32a::2")	// for IPV6
		opt.Option = append(opt.Option, subnet)
		req.Extra = append(req.Extra, opt)
	}

	qname := req.Question[0].Name

	res := make(chan *BindResp, 1)
	var wg sync.WaitGroup
	bindQuery := func(nameserver string) {
		defer wg.Done()
		r, rtt, err := c.Exchange(req, nameserver)
		if err != nil {
			logger.Warn("%s socket error on %s", qname, nameserver)
			logger.Warn("error:%s", err.Error())
			return
		}
		// If SERVFAIL happen, should return immediately and try another upstream resolver.
		// However, other Error code like NXDOMAIN is an clear response stating
		// that it has been verified no such domain existas and ask other resolvers
		// would make no sense. See more about #20
		if r != nil && r.Rcode != dns.RcodeSuccess {
			logger.Warn("%s failed to get an valid answer on %s", qname, nameserver)
			if r.Rcode == dns.RcodeServerFailure {
				return
			}
		}
		re := &BindResp{r, nameserver, rtt}
		select {
		case res <- re:
		default:
		}
	}

	ticker := time.NewTicker(time.Duration(settings.BindServer.Interval) * time.Millisecond)
	defer ticker.Stop()
	// Start lookup on each nameserver top-down, in every second
	//nameServers := r.Nameservers(qname)
	nameServers := []string{}
	nameServers = append (nameServers,
		net.JoinHostPort(settings.BindServer.Host, string(settings.BindServer.Port)))
	//实现：以200ms一个bind请求协程的速度开请求协程向bind list的服务器请求，
	// 任何一个协程获取到数据通过chanel发送，单个协程内部等待回复的时长是5s
	for _, nameServer := range nameServers {
		wg.Add(1)
		go bindQuery(nameServer)
		// but exit early, if we have an answer
		select {
		case re := <-res:
			logger.Debug("%s resolv on %s rtt: %v", UnFqdn(qname), re.nameserver, re.rtt)
			return re.msg, nil
		case <-ticker.C:
			continue
		}
	}
	//如果所有的bind都请求了，但是在这个期间还没有任何协程请求成功，那么等所有协程5s后退出
	// wait for all the namservers to finish
	wg.Wait()
	select {
	case re := <-res:
		logger.Debug("%s resolv on %s rtt: %v", UnFqdn(qname), re.nameserver, re.rtt)
		return re.msg, nil
	default:
		return nil, ResolvError{qname, netType, nameServers}
	}
}

// Namservers return the array of nameservers, with port number appended.
// '#' in the name is treated as port separator, as with dnsmasq.

func (r *BindFind) Nameservers(qname string) []string {
	queryKeys := strings.Split(qname, ".")
	queryKeys = queryKeys[:len(queryKeys)-1] // ignore last '.'

	ns := []string{}
	if v, found := r.domain_server.search(queryKeys); found {
		logger.Debug("%s be found in domain server list, upstream: %v", qname, v)
		server := v
		nameserver := net.JoinHostPort(server, "53")
		ns = append(ns, nameserver)
		//Ensure query the specific upstream nameserver in async Lookup() function.
		return ns
	}

	for _, nameserver := range r.servers {
		ns = append(ns, nameserver)
	}
	return ns
}

func (r *BindFind) Timeout() time.Duration {
	return time.Duration(r.config.Timeout) * time.Second
}
