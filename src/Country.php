<?php

namespace TMT\CL;

use \GeoIp2\Database\Reader;

class Country
{

    /**
     * Check ip is VN or not via maxmind database
     *
     * @param array|string $country_codes
     * @param string|null $ip
     * @return bool
     */
    public static function is($country_codes, $ip = null)
    {
        $ip = empty($ip) ? CloudFlareIP::IP() : $ip;

        // convert to array
        if (!is_array($country_codes)) $country_codes = [$country_codes];

        $country_code = CloudFlareIP::country();
        if (!empty($country_code) && in_array($country_code, $country_codes)) return true;

        // read GeoIp2
        try {

            $database = __DIR__ . '/data/GeoLite2-Country.mmdb';

            $ip_country_code = null;
            $reader = new Reader($database);
            $record = $reader->country($ip);
            if (!empty($record->country->isoCode)) $ip_country_code = $record->country->isoCode;
            if (!empty($ip_country_code) && in_array($ip_country_code, $country_codes)) return true;

        } catch (\Exception $e) {
        }

        return false;
    }

    /**
     * Check ip is VN or not via database txt
     *
     * @param string|null $ip
     * @return bool
     */
    public static function isVN($ip = null)
    {

        $country_code = CloudFlareIP::country();
        if ($country_code === 'VN') return true;

        $ip = empty($ip) ? CloudFlareIP::IP() : $ip;

        if (CloudFlareIP::isIpV4($ip)) {
            $block_ranges = @file_get_contents(__DIR__ . '/data/VN/ipv4.txt');
            $block_ranges = str_replace("\r", null, $block_ranges);
            $block_ranges = explode("\n", $block_ranges);
            foreach ($block_ranges as $range) {
                if (empty($range)) continue;
                if (strpos($range, '#') !== false) continue;
                if (CloudFlareIP::ipv4_in_range($ip, $range)) {
                    return true;
                }
            }
        } else {
            $block_ranges = @file_get_contents(__DIR__ . '/data/VN/ipv6.txt');
            $block_ranges = str_replace("\r", null, $block_ranges);
            $block_ranges = explode("\n", $block_ranges);
            foreach ($block_ranges as $range) {
                if (empty($range)) continue;
                if (strpos($range, '#') !== false) continue;
                if (CloudFlareIP::ipv6_in_range($ip, $range)) {
                    return true;
                }
            }
        }

        return static::is('VN');
    }

}