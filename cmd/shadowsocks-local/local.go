package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

var debug ss.DebugLog

var (
	errAddrType      = errors.New("socks addr type not supported")
	errVer           = errors.New("socks version not supported")
	errMethod        = errors.New("socks only support 1 method now")
	errAuthExtraData = errors.New("socks authentication get extra data")
	errReqExtraData  = errors.New("socks request get extra data")
	errCmd           = errors.New("socks command not supported")
)

const (
	socksVer5       = 5
	socksCmdConnect = 1
)

func init() {
	rand.Seed(time.Now().Unix())
}

func handShake(conn net.Conn) (err error) {
	const (
		idVer     = 0
		idNmethod = 1
	)
	// version identification and method selection message in theory can have
	// at most 256 methods, plus version and nmethod field in total 258 bytes
	// the current rfc defines only 3 authentication methods (plus 2 reserved),
	// so it won't be such long in practice

	buf := make([]byte, 258)

	var n int
	ss.SetReadTimeout(conn)
	// make sure we get the nmethod field
	//
	if n, err = io.ReadAtLeast(conn, buf, idNmethod+1); err != nil {
		return
	}
	if buf[idVer] != socksVer5 {
		return errVer
	}
	nmethod := int(buf[idNmethod])
	msgLen := nmethod + 2
	if n == msgLen { // handshake done, common case
		// do nothing, jump directly to send confirmation
	} else if n < msgLen { // has more methods to read, rare case
		if _, err = io.ReadFull(conn, buf[n:msgLen]); err != nil {
			return
		}
	} else { // error, should not get extra data
		return errAuthExtraData
	}
	// send confirmation: version 5, no authentication required
	_, err = conn.Write([]byte{socksVer5, 0})
	return
}

func getRequest(conn net.Conn) (rawaddr []byte, host string, err error) {
	const (
		idVer   = 0
		idCmd   = 1
		idType  = 3 // address type index
		idIP0   = 4 // ip address start index
		idDmLen = 4 // domain address length index
		idDm0   = 5 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
		lenIPv6   = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
		lenDmBase = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
	)
	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 263)
	var n int
	ss.SetReadTimeout(conn)
	// read till we get possible domain length field
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}
	// check version and cmd
	if buf[idVer] != socksVer5 {
		err = errVer
		return
	}
	if buf[idCmd] != socksCmdConnect {
		err = errCmd
		return
	}

	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm:
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = errAddrType
		return
	}

	if n == reqLen {
		// common case, do nothing
	} else if n < reqLen { // rare case
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else {
		err = errReqExtraData
		return
	}

	rawaddr = buf[idType:reqLen]

	if debug {
		switch buf[idType] {
		case typeIPv4:
			host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
		case typeIPv6:
			host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
		case typeDm:
			host = string(buf[idDm0 : idDm0+buf[idDmLen]])
		}
		port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}

	return
}

type ServerCipher struct {
	server string
	cipher *ss.Cipher
}

var servers struct {
	srvCipher []*ServerCipher
	failCnt   []int // failed connection count
}

// 解析服务器相关的配置
func parseServerConfig(config *ss.Config) {
	// 声明匿名函数获取端口号,如果获取到说明是host:port格式,获取不到则为host
	hasPort := func(s string) bool {
		_, port, err := net.SplitHostPort(s)
		if err != nil {
			return false
		}
		return port != ""
	}
	// 如果服务器密码列表为空,则默认启动命令配置的服务器地址和key
	if len(config.ServerPassword) == 0 {
		// only one encryption table
		cipher, err := ss.NewCipher(config.Method, config.Password)
		if err != nil {
			log.Fatal("Failed generating ciphers:", err)
		}
		// 服务器端口转为int
		srvPort := strconv.Itoa(config.ServerPort)
		// 获取配置文件列表(之前有判断如果是单服务期,将命令行后配置的服务器信息存入服务器列表)
		srvArr := config.GetServerArray()
		//此处len肯定为1
		n := len(srvArr)
		servers.srvCipher = make([]*ServerCipher, n)
		// 遍历服务器列表,实际就一条
		for i, s := range srvArr {
			// 判断服务器host:post格式是否正确
			if hasPort(s) {
				log.Println("ignore server_port option for server", s)
				// 检查通过,设置服务器host:port和ssr密码
				servers.srvCipher[i] = &ServerCipher{s, cipher}
			} else {
				// 获取不到端口号,说明为命令行配置的服务器地址
				servers.srvCipher[i] = &ServerCipher{net.JoinHostPort(s, srvPort), cipher}
			}
		}
	} else {
		// 多服务器配置
		n := len(config.ServerPassword)
		servers.srvCipher = make([]*ServerCipher, n)

		cipherCache := make(map[string]*ss.Cipher)
		i := 0
		// 遍历服务器信息
		for _, serverInfo := range config.ServerPassword {
			if len(serverInfo) < 2 || len(serverInfo) > 3 {
				log.Fatalf("server %v syntax error\n", serverInfo)
			}
			// 服务器host:port
			server := serverInfo[0]
			// 服务器密码
			passwd := serverInfo[1]
			// 加密方法
			encmethod := ""
			// 如果serverInfo长度为3,则说明配置有加密方法
			if len(serverInfo) == 3 {
				// 加密方法
				encmethod = serverInfo[2]
			}
			// 如果获取不到port则说明结构为host而非host:port
			if !hasPort(server) {
				log.Fatalf("no port for server %s\n", server)
			}
			// Using "|" as delimiter is safe here, since no encryption
			// method contains it in the name.
			// 拼接加方法和密码
			cacheKey := encmethod + "|" + passwd
			// 存入map
			cipher, ok := cipherCache[cacheKey]
			// 存入不成功
			if !ok {
				var err error
				// 进行加密
				cipher, err = ss.NewCipher(encmethod, passwd)
				if err != nil {
					log.Fatal("Failed generating ciphers:", err)
				}
				// 设置map的value
				cipherCache[cacheKey] = cipher
			}
			servers.srvCipher[i] = &ServerCipher{server, cipher}
			i++
		}
	}
	servers.failCnt = make([]int, len(servers.srvCipher))
	for _, se := range servers.srvCipher {
		log.Println("available remote server", se.server)
	}
	return
}

func connectToServer(serverId int, rawaddr []byte, addr string) (remote *ss.Conn, err error) {
	se := servers.srvCipher[serverId]
	remote, err = ss.DialWithRawAddr(rawaddr, se.server, se.cipher.Copy())
	if err != nil {
		log.Println("error connecting to shadowsocks server:", err)
		const maxFailCnt = 30
		if servers.failCnt[serverId] < maxFailCnt {
			servers.failCnt[serverId]++
		}
		return nil, err
	}
	debug.Printf("connected to %s via %s\n", addr, se.server)
	servers.failCnt[serverId] = 0
	return
}

// Connection to the server in the order specified in the config. On
// connection failure, try the next server. A failed server will be tried with
// some probability according to its fail count, so we can discover recovered
// servers.
func createServerConn(rawaddr []byte, addr string) (remote *ss.Conn, err error) {
	const baseFailCnt = 20
	n := len(servers.srvCipher)
	skipped := make([]int, 0)
	for i := 0; i < n; i++ {
		// skip failed server, but try it with some probability
		if servers.failCnt[i] > 0 && rand.Intn(servers.failCnt[i]+baseFailCnt) != 0 {
			skipped = append(skipped, i)
			continue
		}
		remote, err = connectToServer(i, rawaddr, addr)
		if err == nil {
			return
		}
	}
	// last resort, try skipped servers, not likely to succeed
	for _, i := range skipped {
		remote, err = connectToServer(i, rawaddr, addr)
		if err == nil {
			return
		}
	}
	return nil, err
}

// 处理连接
func handleConnection(conn net.Conn) {
	if debug {
		debug.Printf("socks connect from %s\n", conn.RemoteAddr().String())
	}
	closed := false
	// 延迟执行关闭连接
	defer func() {
		if !closed {
			conn.Close()
		}
	}()

	var err error = nil
	if err = handShake(conn); err != nil {
		log.Println("socks handshake:", err)
		return
	}
	rawaddr, addr, err := getRequest(conn)
	if err != nil {
		log.Println("error getting request:", err)
		return
	}
	// Sending connection established message immediately to client.
	// This some round trip time for creating socks connection with the client.
	// But if connection failed, the client will get connection reset error.
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x43})
	if err != nil {
		debug.Println("send connection confirmation:", err)
		return
	}

	remote, err := createServerConn(rawaddr, addr)
	if err != nil {
		if len(servers.srvCipher) > 1 {
			log.Println("Failed connect to all available shadowsocks server")
		}
		return
	}
	defer func() {
		if !closed {
			remote.Close()
		}
	}()

	go ss.PipeThenClose(conn, remote, nil)
	ss.PipeThenClose(remote, conn, nil)
	closed = true
	debug.Println("closed connection to", addr)
}

// 开启客户端
func run(listenAddr string) {
	// 使用tcp协议监听listenAddr
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("starting local socks5 server at %v ...\n", listenAddr)
	for {
		// 等待连接
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		// 开启goroutine(并发)
		go handleConnection(conn)
	}
}

func enoughOptions(config *ss.Config) bool {
	return config.Server != nil && config.ServerPort != 0 &&
		config.LocalPort != 0 && config.Password != ""
}

func parseURI(u string, cfg *ss.Config) (string, error) {
	// 如果uri为空返回nil
	if u == "" {
		return "", nil
	}
	// 定义无效URI错误信息
	invalidURI := errors.New("invalid URI")

	// ss协议格式如下
	// ss://base64(method:password)@host:port
	// 去掉uri中标识协议的'ss://'
	u = strings.TrimLeft(u, "ss://")
	// 获取'@'第一次出现u中的位置,不存在返回-1
	i := strings.IndexRune(u, '@')
	var headParts, tailParts [][]byte
	// 如果u中没有@则可能u的值为base64编码
	if i == -1 {
		// 使用base64解码
		dat, err := base64.StdEncoding.DecodeString(u)
		// 解码错误说明u即不包含也不是base64编码,无效的uri
		if err != nil {
			return "", err
		}
		// 如果base64解码成功,使用'@'分割dat(dat即为u解码后的值),返回一个切片
		parts := bytes.Split(dat, []byte("@"))
		// 根据ss格式可知,上面一行代码处理后,切片大小应为2,否则uri无效
		if len(parts) != 2 {
			return "", invalidURI
		}
		// parts[0]实际应为method:password,使用":"分割获取一个包含method和password的切片
		headParts = bytes.SplitN(parts[0], []byte(":"), 2)
		// parts[0]实际应为host:port,使用":"分割获取一个包含host和port的切片
		tailParts = bytes.SplitN(parts[1], []byte(":"), 2)

	} else {
		// 如果u包含"@",则判断uri是否会出现:ss://base64(method:password)@
		if i+1 >= len(u) {
			return "", invalidURI
		}
		// u[i+1:]即获取host:port并使用":"分割获取一个包含host和port的切片
		tailParts = bytes.SplitN([]byte(u[i+1:]), []byte(":"), 2)
		// base64(method:password),解码该部分数据,因为方法和密码经过了base64编码
		dat, err := base64.StdEncoding.DecodeString(u[:i])
		// 解码失败
		if err != nil {
			return "", err
		}
		// 解码成功,dat数据结构应为method:password,使用":"分割获取一个包含method和password的切片
		headParts = bytes.SplitN(dat, []byte(":"), 2)
	}
	// headParts应包含两个元素,分别为method和password的值
	if len(headParts) != 2 {
		return "", invalidURI
	}
	// tailParts也应包含两个元素,分别为host和port的值
	if len(tailParts) != 2 {
		return "", invalidURI
	}
	// 获取method并转为字符串
	cfg.Method = string(headParts[0])
	// 获取password并转为字符串
	cfg.Password = string(headParts[1])
	// 获取port并转为int
	p, e := strconv.Atoi(string(tailParts[1]))
	// 转换失败
	if e != nil {
		return "", e
	}
	cfg.ServerPort = p
	// 返回host字符串
	return string(tailParts[0]), nil

}

func main() {
	log.SetOutput(os.Stdout)

	var configFile, cmdServer, cmdURI string
	var cmdConfig ss.Config
	var printVer bool
	// 获取启动参数中的-version
	flag.BoolVar(&printVer, "version", false, "print version")
	// 获取启动参数中的-c,该值为配置文件名称
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	// 获取启动参数中的-s,即ss服务器ip
	flag.StringVar(&cmdServer, "s", "", "server address")
	// 获取启动参数中的-b,即本地监听地址(ip)
	flag.StringVar(&cmdConfig.LocalAddress, "b", "", "local address, listen only to this address if specified")
	// 获取启动参数中的-k,即加密传输密码,非服务器密码
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	// 获取启动参数中的-p,即ss服务器端口
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	// 获取启动参数中的-t,即客户端与服务端连接超时时间
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds")
	// 获取启动参数中的-l,即本地监听端口
	flag.IntVar(&cmdConfig.LocalPort, "l", 0, "local socks5 proxy port")
	// 获取启动参数中的-m,即加密方法
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-cfb")
	// 获取启动参数中的-d,是否开启debug调试信息
	flag.BoolVar((*bool)(&debug), "d", false, "print debug message")
	// 获取启动参数中的-u,即ss协议URI
	flag.StringVar(&cmdURI, "u", "", "shadowsocks URI")
	// 解析启动参数
	flag.Parse()

	// 解析获取的SS URI并判断解析结果
	if s, e := parseURI(cmdURI, &cmdConfig); e != nil {
		// 解析失败
		log.Printf("invalid URI: %s\n", e.Error())
		flag.Usage()
		// 程序退出
		os.Exit(1)
	} else if s != "" {
		// parseURI 返回的俩结果,一个是host即s,一个是nil即e
		// 解析获取ss服务器地址成功
		cmdServer = s
	}
	// 是否打印ss客户端版本
	if printVer {
		// 打印客户端版本
		ss.PrintVersion()
		os.Exit(0)
	}
	// 配置赋值
	cmdConfig.Server = cmdServer
	// 是否开启debug信息
	ss.SetDebug(debug)
	// 判断文件是否存在(还检查读写等权限)
	exists, err := ss.IsFileExists(configFile)
	// If no config file in current directory, try search it in the binary directory
	// Note there's no portable way to detect the binary directory.
	// 如果当前目录不存在configFile,则获取二进制文件所在目录
	binDir := path.Dir(os.Args[0])
	// 如果IsFileExists检查出错或者文件不存在并且二进制目录不为空或者'.'
	if (!exists || err != nil) && binDir != "" && binDir != "." {
		// 声明新变量
		oldConfig := configFile
		// 拼接配置json文件完成路径
		configFile = path.Join(binDir, "config.json")
		log.Printf("%s not found, try config file %s\n", oldConfig, configFile)
	}
	// 解析configFile文件
	config, err := ss.ParseConfig(configFile)
	if err != nil {
		// 解析异常
		config = &cmdConfig
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", configFile, err)
			os.Exit(1)
		}
	} else {
		// 更新配置文件
		ss.UpdateConfig(config, &cmdConfig)
	}
	// 如果加密方法为空则默认aes-256-cfb
	if config.Method == "" {
		config.Method = "aes-256-cfb"
	}
	// 如果服务器地址(ip:port)和密码的列表空
	if len(config.ServerPassword) == 0 {
		if !enoughOptions(config) {
			fmt.Fprintln(os.Stderr, "must specify server address, password and both server/local port")
			os.Exit(1)
		}
	} else {
		if config.Password != "" || config.ServerPort != 0 || config.GetServerArray() != nil {
			fmt.Fprintln(os.Stderr, "given server_password, ignore server, server_port and password option:", config)
		}
		// 如果本地端口为0(go语言int默认为0)则退出程序
		if config.LocalPort == 0 {
			fmt.Fprintln(os.Stderr, "must specify local port")
			os.Exit(1)
		}
	}

	parseServerConfig(config)
	// 开启本地socket服务器端,LocalAddress:本地ip地址,LocalPort:监听的本地端口,strconv.Itoa()将int转为string
	run(config.LocalAddress + ":" + strconv.Itoa(config.LocalPort))
}
