package com.zyw.btanalyzer.hci

object Assigned {
    val companies = mapOf(
        0x0002 to "Intel", 0x0006 to "Microsoft", 0x000A to "Qualcomm (CSR)", 0x000D to "Texas Instruments",
        0x000F to "Broadcom", 0x004C to "Apple", 0x0059 to "Nordic Semiconductor", 0x005D to "Realtek",
        0x0075 to "Samsung", 0x0087 to "Garmin", 0x009E to "Bose", 0x00C4 to "LG Electronics",
        0x00D2 to "Dialog Semiconductor", 0x00E0 to "Google", 0x012D to "Sony", 0x0157 to "Huami (Amazfit)",
        0x0171 to "Amazon", 0x01AB to "Meta (Facebook)", 0x01DA to "Logitech", 0x027D to "Huawei",
        0x02E5 to "Espressif", 0x02FF to "Silicon Labs", 0x038F to "Xiaomi", 0x006B to "Polar Electro",
        0x0131 to "Cypress", 0x0046 to "MediaTek",
    )
    fun company(id: Int) = companies[id] ?: "Unknown"

    val services16 = mapOf(
        0x1800 to "Generic Access", 0x1801 to "Generic Attribute", 0x1802 to "Immediate Alert", 0x1803 to "Link Loss",
        0x1804 to "Tx Power", 0x1805 to "Current Time", 0x1809 to "Health Thermometer", 0x180A to "Device Information",
        0x180D to "Heart Rate", 0x180F to "Battery", 0x1810 to "Blood Pressure", 0x1812 to "Human Interface Device",
        0x1814 to "Running Speed and Cadence", 0x1816 to "Cycling Speed and Cadence", 0x1818 to "Cycling Power",
        0x1819 to "Location and Navigation", 0x181A to "Environmental Sensing", 0x181C to "User Data",
        0x181D to "Weight Scale", 0x1826 to "Fitness Machine", 0xFE9F to "Google", 0xFEAA to "Eddystone",
        0xFD6F to "Exposure Notification", 0xFE2C to "Google Fast Pair", 0xFE95 to "Xiaomi MiBeacon",
        0xFEE0 to "Huami/Mi Band", 0xFE59 to "Nordic DFU",
    )
    val chars16 = mapOf(
        0x2A00 to "Device Name", 0x2A01 to "Appearance", 0x2A04 to "Preferred Conn Params", 0x2A05 to "Service Changed",
        0x2A06 to "Alert Level", 0x2A07 to "Tx Power Level", 0x2A19 to "Battery Level", 0x2A23 to "System ID",
        0x2A24 to "Model Number", 0x2A25 to "Serial Number", 0x2A26 to "Firmware Revision", 0x2A27 to "Hardware Revision",
        0x2A28 to "Software Revision", 0x2A29 to "Manufacturer Name", 0x2A2B to "Current Time", 0x2A37 to "Heart Rate Measurement",
        0x2A38 to "Body Sensor Location", 0x2A39 to "Heart Rate Control Point", 0x2A4A to "HID Information",
        0x2A4B to "Report Map", 0x2A4C to "HID Control Point", 0x2A4D to "Report", 0x2A4E to "Protocol Mode",
        0x2A50 to "PnP ID", 0x2A6E to "Temperature", 0x2A6F to "Humidity", 0x2AA6 to "Central Address Resolution",
        0x2B29 to "Client Supported Features", 0x2B2A to "Database Hash", 0x2902 to "CCCD", 0x2901 to "User Description",
    )
    fun uuidName(u: String): String? {
        val s = short16(u) ?: return null
        return services16[s] ?: chars16[s]
    }
    /** "0000xxxx-0000-1000-8000-00805f9b34fb" or "xxxx" -> 16-bit value */
    fun short16(u: String): Int? = when {
        u.length == 4 -> u.toIntOrNull(16)
        u.length == 36 && u.lowercase().endsWith("-0000-1000-8000-00805f9b34fb") && u.startsWith("0000") -> u.substring(4, 8).toIntOrNull(16)
        else -> null
    }

    val hciVersions = mapOf(0 to "1.0b", 1 to "1.1", 2 to "1.2", 3 to "2.0+EDR", 4 to "2.1+EDR", 5 to "3.0+HS",
        6 to "4.0", 7 to "4.1", 8 to "4.2", 9 to "5.0", 10 to "5.1", 11 to "5.2", 12 to "5.3", 13 to "5.4", 14 to "6.0")

    val lmpFeatures = mapOf(
        0 to "3-slot packets", 1 to "5-slot packets", 2 to "Encryption", 3 to "Slot offset", 4 to "Timing accuracy",
        5 to "Role switch", 6 to "Hold mode", 7 to "Sniff mode", 9 to "Power control requests", 10 to "CQDDR",
        11 to "SCO link", 12 to "HV2 packets", 13 to "HV3 packets", 14 to "u-law", 15 to "A-law", 16 to "CVSD",
        17 to "Paging param negotiation", 18 to "Power control", 19 to "Transparent SCO", 25 to "EDR ACL 2 Mb/s",
        26 to "EDR ACL 3 Mb/s", 27 to "Enhanced inquiry scan", 28 to "Interlaced inquiry scan", 29 to "Interlaced page scan",
        30 to "RSSI with inquiry results", 31 to "eSCO link (EV3)", 32 to "EV4", 33 to "EV5", 35 to "AFH capable slave",
        36 to "AFH classification slave", 37 to "BR/EDR Not Supported", 38 to "LE Supported (Controller)",
        39 to "3-slot EDR ACL", 40 to "5-slot EDR ACL", 41 to "Sniff subrating", 42 to "Pause encryption",
        43 to "AFH capable master", 44 to "AFH classification master", 45 to "EDR eSCO 2 Mb/s", 46 to "EDR eSCO 3 Mb/s",
        47 to "3-slot EDR eSCO", 48 to "Extended Inquiry Response", 49 to "Simultaneous LE and BR/EDR",
        51 to "Secure Simple Pairing", 52 to "Encapsulated PDU", 53 to "Erroneous Data Reporting",
        54 to "Non-flushable Packet Boundary Flag", 56 to "Link Supervision Timeout Changed Event",
        57 to "Inquiry TX Power Level", 58 to "Enhanced Power Control", 63 to "Extended features",
    )
    val leFeatures = mapOf(0 to "LE Encryption", 1 to "Connection Parameters Request", 2 to "Extended Reject Indication",
        3 to "Slave-initiated Features Exchange", 4 to "LE Ping", 5 to "Data Packet Length Extension", 6 to "LL Privacy",
        7 to "Extended Scanner Filter Policies", 8 to "LE 2M PHY", 11 to "LE Coded PHY", 12 to "Extended Advertising")

    val errors = mapOf(0x00 to "Success", 0x01 to "Unknown HCI Command", 0x02 to "Unknown Connection ID",
        0x05 to "Authentication Failure", 0x08 to "Connection Timeout", 0x0C to "Command Disallowed",
        0x11 to "Unsupported Feature/Param", 0x12 to "Invalid HCI Params", 0x13 to "Remote User Terminated",
        0x16 to "Local Host Terminated", 0x1A to "Unsupported Remote Feature", 0x22 to "LL Response Timeout",
        0x3B to "Unacceptable Conn Params", 0x3E to "Failed to Establish Connection")
    fun err(c: Int) = "0x%02X %s".format(c, errors[c] ?: "")

    val attErrors = mapOf(1 to "Invalid Handle", 2 to "Read Not Permitted", 3 to "Write Not Permitted", 5 to "Insufficient Authentication",
        6 to "Request Not Supported", 7 to "Invalid Offset", 8 to "Insufficient Authorization", 0x0A to "Attribute Not Found",
        0x0C to "Insufficient Encryption Key Size", 0x0E to "Unlikely Error", 0x0F to "Insufficient Encryption")

    fun cod(c: Int): String {
        val major = when ((c shr 8) and 0x1f) { 0 -> "Misc"; 1 -> "Computer"; 2 -> "Phone"; 3 -> "Network AP"; 4 -> "Audio/Video"
            5 -> "Peripheral"; 6 -> "Imaging"; 7 -> "Wearable"; 8 -> "Toy"; 9 -> "Health"; else -> "Uncategorized" }
        return "%s (0x%06X)".format(major, c)
    }
}
