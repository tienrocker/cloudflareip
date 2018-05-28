<?php

namespace TMT\CL;

class Error503
{
    function __construct()
    {
        header('HTTP/1.0 503 Service Unavailable');
        $this->__toString();
    }

    function __toString()
    {
        return '<html>
<head>
    <title>Error 503 Service Unavailable</title>
</head>
<body>
<h1>503 Service Unavailable</h1>
Our apologies for the temporary inconvenience. The requested URL generated 503 "Service Unavailable" error due to overloading or maintenance of the server.
</body>
</html>';
    }
}