/**
 * Created with IntelliJ IDEA.
 * User: clowwindy
 * Date: 12-11-2
 * Time: 上午10:31
 * To change this template use File | Settings | File Templates.
 */
package shadowsocks

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	// "log"
	"os"
	"reflect"
	"time"
)

type Config struct {
	Server       interface{} `json:"server"`
	ServerPort   int         `json:"server_port"`
	LocalPort    int         `json:"local_port"`
	LocalAddress string      `json:"local_address"`
	Password     string      `json:"password"`
	Method       string      `json:"method"` // encryption method

	// following options are only used by server
	PortPassword map[string]string `json:"port_password"`
	Timeout      int               `json:"timeout"`

	// following options are only used by client

	// The order of servers in the client config is significant, so use array
	// instead of map to preserve the order.
	ServerPassword [][]string `json:"server_password"`
}

var readTimeout time.Duration

// 获取ss服务器列表
func (config *Config) GetServerArray() []string {
	// Specifying multiple servers in the "server" options is deprecated.
	// But for backward compatibility, keep this.
	// 如果服务器地址为空
	if config.Server == nil {
		return nil
	}
	// 获取启动命令配置的单个服务器地址
	single, ok := config.Server.(string)
	// 如果获取成功则返回单个服务器
	if ok {
		return []string{single}
	}
	// 获取配置文件中服务器列表
	arr, ok := config.Server.([]interface{})
	if ok {
		/*
			if len(arr) > 1 {
				log.Println("Multiple servers in \"server\" option is deprecated. " +
					"Please use \"server_password\" instead.")
			}
		*/
		// 创建切片
		serverArr := make([]string, len(arr), len(arr))
		for i, s := range arr {
			// 服务器ip:port字符串,如果不是字符串就会出现下面的异常
			serverArr[i], ok = s.(string)
			// 获取string类型异常
			if !ok {
				goto typeError
			}
		}
		return serverArr
	}
	// 	goto的标记点
typeError:
	panic(fmt.Sprintf("Config.Server type error %v", reflect.TypeOf(config.Server)))
}

// 解析configFile
func ParseConfig(path string) (config *Config, err error) {
	// 读取配置文件
	file, err := os.Open(path) // For read access.
	// 读取失败,返回nil
	if err != nil {
		return
	}
	// 延迟关闭文件
	defer file.Close()
	// 读取文件所有内容
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}
	// 实例化Congfig结构体
	config = &Config{}
	// 解析文件数据并初始化config
	if err = json.Unmarshal(data, config); err != nil {
		return nil, err
	}
	// 获取解析的congfig中的读取超时时间转为毫秒
	readTimeout = time.Duration(config.Timeout) * time.Second
	return
}

func SetDebug(d DebugLog) {
	Debug = d
}

// 更新config,主要是覆盖启动参数中相同的参数
func UpdateConfig(old, new *Config) {
	// Using reflection here is not necessary, but it's a good exercise.
	// For more information on reflections in Go, read "The Laws of Reflection"
	// http://golang.org/doc/articles/laws_of_reflection.html
	// 通过反射获取Config属性
	newVal := reflect.ValueOf(new).Elem()
	oldVal := reflect.ValueOf(old).Elem()

	// typeOfT := newVal.Type()
	for i := 0; i < newVal.NumField(); i++ {
		newField := newVal.Field(i)
		oldField := oldVal.Field(i)
		// log.Printf("%d: %s %s = %v\n", i,
		// typeOfT.Field(i).Name, newField.Type(), newField.Interface())
		switch newField.Kind() {
		case reflect.Interface:
			if fmt.Sprintf("%v", newField.Interface()) != "" {
				oldField.Set(newField)
			}
		case reflect.String:
			s := newField.String()
			if s != "" {
				oldField.SetString(s)
			}
		case reflect.Int:
			i := newField.Int()
			if i != 0 {
				oldField.SetInt(i)
			}
		}
	}

	old.Timeout = new.Timeout
	readTimeout = time.Duration(old.Timeout) * time.Second
}
