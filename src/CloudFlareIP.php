<?php

namespace TMT\CL;

class CloudFlareIP
{

    /**
     * https://www.cloudflare.com/ips-v4
     * @var string
     */
    private static $_ips_v4 = <<< EOT
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
104.16.0.0/12
108.162.192.0/18
131.0.72.0/22
141.101.64.0/18
162.158.0.0/15
172.64.0.0/13
173.245.48.0/20
188.114.96.0/20
190.93.240.0/20
197.234.240.0/22
198.41.128.0/17
EOT;

    /**
     * https://www.cloudflare.com/ips-v6
     * @var string
     */
    private static $_ips_v6 = <<< EOT
2400:cb00::/32
2405:8100::/32
2405:b500::/32
2606:4700::/32
2803:f800::/32
2c0f:f248::/32
2a06:98c0::/29
EOT;

    /**
     * @var string|null
     */
    private static $_real_ip = null;

    /**
     * Get real IP of user via cloudflare proxy
     * @return string|null
     */
    public static function IP()
    {
        if (static::$_real_ip !== null) return static::$_real_ip;

        $ips = array();
        if (isset($_SERVER['HTTP_CLIENT_IP']))
            $ips[] = $_SERVER['HTTP_CLIENT_IP'];
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR']))
            $ips[] = $_SERVER['HTTP_X_FORWARDED_FOR'];
        if (isset($_SERVER['HTTP_X_FORWARDED']))
            $ips[] = $_SERVER['HTTP_X_FORWARDED'];
        if (isset($_SERVER['HTTP_FORWARDED_FOR']))
            $ips[] = str_replace(array('for', '=', '[', ']', '"'), null, $_SERVER['HTTP_FORWARDED_FOR']);
        if (isset($_SERVER['HTTP_FORWARDED']))
            $ips[] = str_replace(array('for', '=', '[', ']', '"'), null, $_SERVER['HTTP_FORWARDED']);
        if (isset($_SERVER['HTTP_CF_CONNECTING_IP']))
            $ips[] = $_SERVER['HTTP_CF_CONNECTING_IP'];
        if (isset($_SERVER['REMOTE_ADDR']))
            $ips[] = $_SERVER['REMOTE_ADDR'];

        foreach ($ips as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP) && !static::is_cloudflare_ip($ip)) {
                static::$_real_ip = $ip;
                break;
            }
        }

        return static::$_real_ip;
    }

    /**
     * Check is cloudflare ip
     * @param $ip
     * @return bool
     */
    public static function is_cloudflare_ip($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return false; // invalid ip

        if (static::isIpV4($ip)) {
            $cf_ip_ranges = explode(PHP_EOL, static::$_ips_v4);
            foreach ($cf_ip_ranges as $range) {
                if (empty($range)) continue;
                if (static::ipv4_in_range($ip, $range)) {
                    return true;
                }
            }
        } else {
            $cf_ip_ranges = explode(PHP_EOL, static::$_ips_v6);
            foreach ($cf_ip_ranges as $range) {
                if (empty($range)) continue;
                if (static::ipv6_in_range($ip, $range)) {
                    return true;
                }
            }
        }

        return false;
    }

    /*
     * ip_in_range.php - Function to determine if an IP is located in a
     *                   specific range as specified via several alternative
     *                   formats.
     *
     * Network ranges can be specified as:
     * 1. Wildcard format:     1.2.3.*
     * 2. CIDR format:         1.2.3/24  OR  1.2.3.4/255.255.255.0
     * 3. Start-End IP format: 1.2.3.0-1.2.3.255
     *
     * Return value BOOLEAN : ip_in_range($ip, $range);
     *
     * Copyright 2008: Paul Gregg <pgregg@pgregg.com>
     * 10 January 2008
     * Version: 1.2
     *
     * Source website: http://www.pgregg.com/projects/php/ip_in_range/
     * Version 1.2
     *
     * This software is Donationware - if you feel you have benefited from
     * the use of this tool then please consider a donation. The value of
     * which is entirely left up to your discretion.
     * http://www.pgregg.com/donate/
     *
     * Please do not remove this header, or source attibution from this file.
     */

    /*
    * Modified by James Greene <james@cloudflare.com> to include IPV6 support
    * (original version only supported IPV4).
    * 21 May 2012
    */

    // decbin32
    // In order to simplify working with IP addresses (in binary) and their
    // netmasks, it is easier to ensure that the binary strings are padded
    // with zeros out to 32 characters - IP addresses are 32 bit numbers
    private static function decbin32($dec)
    {
        return str_pad(decbin($dec), 32, '0', STR_PAD_LEFT);
    }

    // ipv4_in_range
    // This function takes 2 arguments, an IP address and a 'range' in several
    // different formats.
    // Network ranges can be specified as:
    // 1. Wildcard format:     1.2.3.*
    // 2. CIDR format:         1.2.3/24  OR  1.2.3.4/255.255.255.0
    // 3. Start-End IP format: 1.2.3.0-1.2.3.255
    // The function will return true if the supplied IP is within the range.
    // Note little validation is done on the range inputs - it expects you to
    // use one of the above 3 formats.
    public static function ipv4_in_range($ip, $range)
    {
        if (strpos($range, '/') !== false) {
            // $range is in IP/NETMASK format
            list($range, $netmask) = explode('/', $range, 2);
            if (strpos($netmask, '.') !== false) {
                // $netmask is a 255.255.0.0 format
                $netmask = str_replace('*', '0', $netmask);
                $netmask_dec = ip2long($netmask);
                return ((ip2long($ip) & $netmask_dec) == (ip2long($range) & $netmask_dec));
            } else {
                // $netmask is a CIDR size block
                // fix the range argument
                $x = explode('.', $range);
                while (count($x) < 4) $x[] = '0';
                list($a, $b, $c, $d) = $x;
                $range = sprintf('%u.%u.%u.%u', empty($a) ? '0' : $a, empty($b) ? '0' : $b, empty($c) ? '0' : $c, empty($d) ? '0' : $d);
                $range_dec = ip2long($range);
                $ip_dec = ip2long($ip);

                # Strategy 1 - Create the netmask with 'netmask' 1s and then fill it to 32 with 0s
                #$netmask_dec = bindec(str_pad('', $netmask, '1') . str_pad('', 32-$netmask, '0'));

                # Strategy 2 - Use math to create it
                $wildcard_dec = pow(2, (32 - $netmask)) - 1;
                $netmask_dec = ~$wildcard_dec;

                return (($ip_dec & $netmask_dec) == ($range_dec & $netmask_dec));
            }
        } else {
            // range might be 255.255.*.* or 1.2.3.0-1.2.3.255
            if (strpos($range, '*') !== false) { // a.b.*.* format
                // Just convert to A-B format by setting * to 0 for A and 255 for B
                $lower = str_replace('*', '0', $range);
                $upper = str_replace('*', '255', $range);
                $range = sprintf('%s-%s', $lower, $upper);
            }

            if (strpos($range, '-') !== false) { // A-B format
                list($lower, $upper) = explode('-', $range, 2);
                $lower_dec = (float)sprintf('%u', ip2long($lower));
                $upper_dec = (float)sprintf('%u', ip2long($upper));
                $ip_dec = (float)sprintf('%u', ip2long($ip));
                return (($ip_dec >= $lower_dec) && ($ip_dec <= $upper_dec));
            }
            return false;
        }
    }

    private static function ip2long6($ip)
    {
        if (substr_count($ip, '::')) {
            $ip = str_replace('::', str_repeat(':0000', 8 - substr_count($ip, ':')) . ':', $ip);
        }

        $ip = explode(':', $ip);
        $r_ip = '';
        foreach ($ip as $v) {
            $r_ip .= str_pad(base_convert($v, 16, 2), 16, 0, STR_PAD_LEFT);
        }

        return base_convert($r_ip, 2, 10);
    }

    // Get the ipv6 full format and return it as a decimal value.
    private static function get_ipv6_full($ip)
    {
        $pieces = explode('/', $ip, 2);
        $left_piece = $pieces[0];
        $right_piece = $pieces[1];

        // Extract out the main IP pieces
        $ip_pieces = explode('::', $left_piece, 2);
        $main_ip_piece = $ip_pieces[0];
        $last_ip_piece = $ip_pieces[1];

        // Pad out the shorthand entries.
        $main_ip_pieces = explode(':', $main_ip_piece);
        foreach ($main_ip_pieces as $key => $val) {
            $main_ip_pieces[$key] = str_pad($main_ip_pieces[$key], 4, '0', STR_PAD_LEFT);
        }

        // Check to see if the last IP block (part after ::) is set
        $last_piece = '';
        $size = count($main_ip_pieces);
        if (trim($last_ip_piece) != '') {
            $last_piece = str_pad($last_ip_piece, 4, '0', STR_PAD_LEFT);

            // Build the full form of the IPV6 address considering the last IP block set
            for ($i = $size; $i < 7; $i++) {
                $main_ip_pieces[$i] = '0000';
            }
            $main_ip_pieces[7] = $last_piece;
        } else {
            // Build the full form of the IPV6 address
            for ($i = $size; $i < 8; $i++) {
                $main_ip_pieces[$i] = '0000';
            }
        }

        // Rebuild the final long form IPV6 address
        $final_ip = implode(':', $main_ip_pieces);

        return static::ip2long6($final_ip);
    }


    // Determine whether the IPV6 address is within range.
    // $ip is the IPV6 address in decimal format to check if its within the IP range created by the cloudflare IPV6 address, $range_ip.
    // $ip and $range_ip are converted to full IPV6 format.
    // Returns true if the IPV6 address, $ip,  is within the range from $range_ip.  False otherwise.
    public static function ipv6_in_range($ip, $range_ip)
    {
        $pieces = explode('/', $range_ip, 2);
        $left_piece = $pieces[0];
        $right_piece = $pieces[1];

        // Extract out the main IP pieces
        $ip_pieces = explode('::', $left_piece, 2);
        $main_ip_piece = $ip_pieces[0];
        $last_ip_piece = $ip_pieces[1];

        // Pad out the shorthand entries.
        $main_ip_pieces = explode(':', $main_ip_piece);
        foreach ($main_ip_pieces as $key => $val) {
            $main_ip_pieces[$key] = str_pad($main_ip_pieces[$key], 4, '0', STR_PAD_LEFT);
        }

        // Create the first and last pieces that will denote the IPV6 range.
        $first = $main_ip_pieces;
        $last = $main_ip_pieces;

        // Check to see if the last IP block (part after ::) is set
        $last_piece = '';
        $size = count($main_ip_pieces);
        if (trim($last_ip_piece) != '') {
            $last_piece = str_pad($last_ip_piece, 4, '0', STR_PAD_LEFT);

            // Build the full form of the IPV6 address considering the last IP block set
            for ($i = $size; $i < 7; $i++) {
                $first[$i] = '0000';
                $last[$i] = 'ffff';
            }
            $main_ip_pieces[7] = $last_piece;
        } else {
            // Build the full form of the IPV6 address
            for ($i = $size; $i < 8; $i++) {
                $first[$i] = '0000';
                $last[$i] = 'ffff';
            }
        }

        // Rebuild the final long form IPV6 address
        $first = static::ip2long6(implode(':', $first));
        $last = static::ip2long6(implode(':', $last));
        $in_range = ($ip >= $first && $ip <= $last);

        return $in_range;
    }

    public static function country()
    {
        return @$_SERVER['HTTP_CF_IPCOUNTRY'];
    }

    public static function isIpV4($ip)
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    }

    public static function isIpV6($ip)
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    }
}
