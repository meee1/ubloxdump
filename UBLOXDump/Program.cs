using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using MissionPlanner.Comms;
using System.Security.Cryptography;

namespace UBLOXDump
{
    internal class Program
    {
        private static readonly BinaryWriter bw =
            new BinaryWriter(File.Open("data.raw", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read));

        private static byte UBX_class;
        private static byte UBX_id;
        private static byte UBX_payload_length_hi;
        private static readonly int UBX_MAXPAYLOAD = 1000;
        private static byte ck_a;
        private static byte ck_b;
        private static byte UBX_payload_length_lo;
        private static byte UBX_ck_a;
        private static byte UBX_ck_b;
        private static int UBX_payload_counter;
        private static readonly byte[] UBX_buffer = new byte[256];
        private static int UBX_step;
        private static uploadreq req;

        //http://gps.0xdc.ru/wiki/doku.php?id=u-blox_undocumented_messages

        public class msginfo
        {
            public string name;
            public byte cl;
            public byte id;

            public msginfo()
            {
                
            }

            public msginfo(string name, byte cl, byte id)
            {
                this.name = name;
                this.cl = cl;
                this.id = id;
            }
        }

                 /* 
         *v8 09 0b - set addr // B5 62 09 0B 05 00 00 00 80 00 01 9A 4D
         *   09 0c - data
         *   09 0d
         *   09 07 - safeboot
         *   09 0e - finish
         *   09 06 - identify
         *   09 21 - UPD-DOWNL
         *   09 08 - start addr ? // B5 62 09 08 04 00 00 00 80 00 95 98
         *   09 20 - UPD-UPLOAD
         */

        public static List<msginfo> msglist = new List<msginfo>()
        {
            new msginfo("ACK-ACK", 0x05, 0x01),
            new msginfo("ACK-NACK", 0x05, 0x00),
            new msginfo("AID-ALM", 0x0b, 0x30),
            new msginfo("AID-ALPSRV", 0XB, 32),
            new msginfo("AID-DATA", 0x0b, 0x10),
            new msginfo("AID-EPH", 0x0b, 0x31),
            new msginfo("AID-HUI", 0x0b, 0x02),
            new msginfo("AID-INI", 0x0b, 0x01),
            new msginfo("AID-REQ", 0x0b, 0x00),
            new msginfo("CFG-ANT", 0x06, 0x13),
            new msginfo("CFG-CFG", 0x06, 0x09),
            new msginfo("CFG-DAT", 0x06, 0x06),
            new msginfo("CFG-EKF", 0x06, 0x12),
            new msginfo("CFG-FXN", 0x06, 0x0e),
            new msginfo("CFG-INF", 0x06, 0x02),
            new msginfo("CFG-LIC", 0x06, 0x80),
            new msginfo("CFG-MSG", 0x06, 0x01),
            new msginfo("CFG-NAV2", 0x06, 0x1a),
            new msginfo("CFG-NMEA", 0x06, 0x17),
            new msginfo("CFG-PRT", 0x06, 0x00),
            new msginfo("CFG-RATE", 0x06, 0x08),
            new msginfo("CFG-RST", 0x06, 0x04),
            new msginfo("CFG-RXM", 0x06, 0x11),
            new msginfo("CFG-SBAS", 0x06, 0x16),
            new msginfo("CFG-TM", 0x06, 0x10),
            new msginfo("CFG-TM2", 0x06, 0x19),
            new msginfo("CFG-TMODE", 0x06, 0x1d),
            new msginfo("CFG-TMODE3", 6, 0x71),
            new msginfo("CFG-TP", 0x06, 0x07),
            new msginfo("CFG-USB", 0x06, 0x1b),
            new msginfo("INF-DEBUG", 0x04, 0x04),
            new msginfo("INF-ERROR", 0x04, 0x00),
            new msginfo("INF-NOTICE", 0x04, 0x02),
            new msginfo("INF-TEST", 0x04, 0x03),
            new msginfo("INF-USER", 0x04, 0x07),
            new msginfo("INF-WARNING", 0x04, 0x01),
            new msginfo("LOG-INFO", 0X21, 8),
            new msginfo("MON-EXCEPT", 0x0a, 0x05),
            new msginfo("MON-HW", 0x0a, 0x09),
            new msginfo("MON-HW2", 0XA, 0XB),
            new msginfo("MON-IO", 0x0a, 0x02),
            new msginfo("MON-IPC", 0x0a, 0x03),
            new msginfo("MON-LLC", 0xa, 0xd),
            new msginfo("MON-MSGPP", 0x0a, 0x06),
            new msginfo("MON-RXBUF", 0x0a, 0x07),
            new msginfo("MON-SCHD", 0x0a, 0x01),
            new msginfo("MON-SPEC", 0x0a, 0x1d),
            new msginfo("MON-TXBUF", 0x0a, 0x08),
            new msginfo("MON-USB", 0x0a, 0x0a),
            new msginfo("MON-VER", 0x0a, 0x04),
            new msginfo("NAV-AOPSTATUS", 0x01, 0X60),
            new msginfo("NAV-CLOCK", 0x01, 0x22),
            new msginfo("NAV-DGPS", 0x01, 0x31),
            new msginfo("NAV-DOP", 0x01, 0x04),
            new msginfo("NAV-EKFSTATUS", 0x01, 0x40),
            new msginfo("NAV-GEOFENCE", 0X1, 0X39),
            new msginfo("NAV-ODO", 0X1, 0X9),
            new msginfo("NAV-ORB", 0X1, 0X34),
            new msginfo("NAV-POSECEF", 0x01, 0x01),
            new msginfo("NAV-POSLLH", 0x01, 0x02),
            new msginfo("NAV-POSUTM", 0x01, 0x08),
            new msginfo("NAV-PVT", 0x01, 0x07),
            new msginfo("NAV-RELPOSNED", 0X1, 0X3C),
            new msginfo("NAV-SAT", 0X1, 0X35),
            new msginfo("NAV-SBAS", 0x01, 0x32),
            new msginfo("NAV-SOL", 0x01, 0x06),
            new msginfo("NAV-STATUS", 0x01, 0x03),
            new msginfo("NAV-SVIN", 0X1, 0X3B),
            new msginfo("NAV-SVINFO", 0x01, 0x30),
            new msginfo("NAV-TIMEBDS", 0X1, 0X24),
            new msginfo("NAV-TIMEGLO", 0X1, 0X23),
            new msginfo("NAV-TIMEGPS", 0x01, 0x20),
            new msginfo("NAV-TIMELS", 0X1, 0X26),
            new msginfo("NAV-TIMEUTC", 0x01, 0x21),
            new msginfo("NAV-VELECEF", 0x01, 0x11),
            new msginfo("NAV-VELNED", 0x01, 0x12),
            new msginfo("NMEA", 0xf0, 0),
            new msginfo("NMEA", 0xf0, 1),
            new msginfo("NMEA", 0xf0, 10),
            new msginfo("NMEA", 0xf0, 11),
            new msginfo("NMEA", 0xf0, 12),
            new msginfo("NMEA", 0xf0, 13),
            new msginfo("NMEA", 0xf0, 14),
            new msginfo("NMEA", 0xf0, 15),
            new msginfo("NMEA", 0xf0, 2),
            new msginfo("NMEA", 0xf0, 3),
            new msginfo("NMEA", 0xf0, 4),
            new msginfo("NMEA", 0xf0, 5),
            new msginfo("NMEA", 0xf0, 6),
            new msginfo("NMEA", 0xf0, 7),
            new msginfo("NMEA", 0xf0, 8),
            new msginfo("NMEA", 0xf0, 9),
            new msginfo("pubx00", 0xf1, 0),
            new msginfo("pubx01", 0xf1, 1),
            new msginfo("pubx03", 0xf1, 3),
            new msginfo("pubx04", 0xf1, 4),
            new msginfo("RTCM1005", 0XF5, 0x05),
            new msginfo("RTCM1077", 0XF5, 0X4D),
            new msginfo("RTCM1087", 0XF5, 0x57),
            new msginfo("RXM-ALM", 0x02, 0x30),
            new msginfo("RXM-ALM", 0x02, 0x30),
            new msginfo("RXM-EPH", 0x02, 0x31),
            new msginfo("RXM-EPH", 0x02, 0x31),
            new msginfo("RXM-MEASX", 0x02, 0x14),
            new msginfo("RXM-POSREQ", 0x02, 0x40),
            new msginfo("RXM-RAW", 0x02, 0x10),
            new msginfo("RXM-RAWX", 0x02, 0x15),
            new msginfo("RXM-SFRB", 0x02, 0x11),
            new msginfo("RXM-SFRBX", 0x02, 0x13),
            new msginfo("RXM-SVSI", 0x02, 0x20),
            new msginfo("SEC-SIGN", 0X27, 1),
            new msginfo("SEC-UNIQID", 0X27, 3),
            new msginfo("TIM-SVIN", 0x0d, 0x04),
            new msginfo("TIM-TM", 0x0d, 0x02),
            new msginfo("TIM-TM2", 0x0d, 0x03),
            new msginfo("TIM-TP", 0x0d, 0x01),
            new msginfo("TRK-MEAS", 3, 0x10),
            new msginfo("TRK-SFRB", 3, 0x2),
            new msginfo("TRK-SFRBX", 3, 0xf),
            new msginfo("TRK-TRKD2", 3, 0x6),
            new msginfo("TRK-TRKD5", 3, 0x0a),
            new msginfo("UPD", 9, 0xff),
            new msginfo("UPD-csum", 9, 0xd),
            new msginfo("UPD-DOWNL", 0x09, 0x01),
            new msginfo("UPD-DOWNL-SEC", 0x09, 0x21),
            new msginfo("UPD-erase", 9, 0xb),
            new msginfo("UPD-EXEC", 0x09, 0x03),
            new msginfo("UPD-EXEC-SEC", 0x09, 0x22),
            new msginfo("UPD-FLDET", 9, 8),
            new msginfo("UPD-identify", 9, 6),
            new msginfo("UPD-MEMCPY", 0x09, 0x04),
            new msginfo("UPD-RBOOT", 9, 0xe), // EXIT
            new msginfo("UPD-SAFE", 9, 7), // ENTER
            new msginfo("UPD-SOS", 9, 0x14),
            new msginfo("UPD-UPLOAD", 0x09, 0x02),
            new msginfo("UPD-UPLOAD-SEC", 0x09, 0x20),
            new msginfo("UPD-write", 9, 0xc),

        };

        public static msginfo GetMsginfo(byte cl, byte id)
        {
            var list = msglist.Where(a => a.cl == cl && a.id == id);

            if(list.Count() == 0)
                return new msginfo("UNKNOWN",0,0);

            return list.First();
        }

        static byte[] sha256(byte[] seed, byte[] packet)
        {
            using (SHA256Managed signit = new SHA256Managed())
            {
                signit.TransformBlock(seed, 0, seed.Length, null, 0);
                signit.TransformFinalBlock(packet, 0, packet.Length);
                var ctx = signit.Hash;

                return ctx;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="file">raw dump</param>
        /// <param name="outputfile">output</param>
        /// <param name="startoffset">Memory location</param>
        /// <param name="secondsoffset">Flash location</param>
        private static void ExtractPacketAddresses(string file, string outputfile, int startoffset,
            int secondsoffset = 0, bool m8 = false)
        {
            if (!File.Exists(file))
                return;

            TextWriter tw = new StreamWriter(outputfile);

            var br = new BinaryReader(File.OpenRead(file));

            // 0x1420 - 6m
            // 0x3e4c - 7n

            br.BaseStream.Seek(startoffset, SeekOrigin.Begin);

            var lowestoffset = uint.MaxValue;

            while (br.BaseStream.Position < (startoffset + 4000))
            {
                var posstart = br.BaseStream.Position;
                var addr = br.ReadUInt32();
                if (addr != 0)
                    lowestoffset = Math.Min(addr, lowestoffset);
                br.BaseStream.Seek(2, SeekOrigin.Current);
                var clas = br.ReadByte();
                var subclas = br.ReadByte();
                br.BaseStream.Seek(12, SeekOrigin.Current);

                var pos = br.BaseStream.Position;

                ulong ch = 0;

                if (br.BaseStream.Length > addr)
                {
                    br.BaseStream.Seek(addr, SeekOrigin.Begin);

                    ch = br.ReadUInt64();

                    br.BaseStream.Seek(pos, SeekOrigin.Begin);
                }

                var type = GetMsginfo(clas, subclas);

                var name = type.name;

                tw.WriteLine(posstart.ToString("X") + "\t" + clas.ToString("X") + "\t" + subclas.ToString("X") + "\t" +
                             addr.ToString("X") + "\t" + ch.ToString("X") + "\t" + name);
            }

            //
            while (br.BaseStream.Position < (startoffset + 2000 + 320))
            {
                var addr = br.ReadUInt32();
                tw.WriteLine(addr.ToString("X"));
            }

            tw.WriteLine("Message in FW");

            //second
            if (secondsoffset > 0)
            {
                br.BaseStream.Seek(secondsoffset, SeekOrigin.Begin);

                try
                {
                    while (br.BaseStream.Position < (secondsoffset + 0x928))
                    {
                        var posstart = br.BaseStream.Position;

                        var clas = br.ReadByte();
                        var subclas = br.ReadByte();

                        br.BaseStream.Seek(2, SeekOrigin.Current);

                        var addr = br.ReadUInt32();

                        if (!m8)
                            br.BaseStream.Seek(4, SeekOrigin.Current);

                        if (clas == 0 && subclas == 0)
                            continue;

                        var type = GetMsginfo(clas, subclas);

                        var name = type.name;

                        tw.WriteLine(posstart.ToString("X") + "\t" + clas.ToString("X") + "\t" + subclas.ToString("X") +
                                     "\t" + addr.ToString("X") + "\t" + name);
                    }
                }
                catch
                {
                }
            }

            tw.Close();

            br.Close();
        }

        private static void pollmessage(Stream port, byte[] header, byte clas, byte subclass)
        {
            //B5 62 02 31 00 00 33 9B 

            byte[] datastruct1 = {clas, subclass, 0, 0};

            var checksum1 = ubx_checksum(datastruct1, datastruct1.Length);

            port.Write(header, 0, header.Length);
            port.Write(datastruct1, 0, datastruct1.Length);
            port.Write(checksum1, 0, checksum1.Length);
        }

        private static void turnon(Stream port, byte[] header, byte clas, byte subclass)
        {
            //B5 62 06 01 03 00 02 30 01 3D A6

            byte[] datastruct1 = {0x6, 0x1, 0x3, 0x0, clas, subclass, 1};

            var checksum1 = ubx_checksum(datastruct1, datastruct1.Length);

            port.Write(header, 0, header.Length);
            port.Write(datastruct1, 0, datastruct1.Length);
            port.Write(checksum1, 0, checksum1.Length);
        }

        private static void Main(string[] args)
        {
            ExtractPacketAddresses("ublox 6mdata.raw", "Addrneo6m.txt", 0x1420, 0x26ddf4);

            ExtractPacketAddresses("6mdata.raw", "Addrneo6m-2.txt", 0x1420, 0x26ddf4);

            ExtractPacketAddresses("datalea6h.raw", "Addrlea6h.txt", 0x3e4c, 0x8546dc);

            ExtractPacketAddresses("datalea6h-nu602.raw", "Addrlea6hnu602.txt", 0x3e4c, 0x8546dc);

            ExtractPacketAddresses("dataneo7n.raw", "Addrneo7n.txt", 0x20001188, 0x862f0c);

            ExtractPacketAddresses("UBX_M8_301_HPG_111_REFERENCE_NEOM8P2.b45d5e63c7aa261bd58dfbcbc22bad68.bin",
                "Addrm8p.txt", 0, 0x6df34, true);

            ExtractPacketAddresses("UBX_M8_301_HPG_111_REFERENCE_NEOM8P2.b45d5e63c7aa261bd58dfbcbc22bad68.bin",
               "Addrm8p22.txt", 0, 0x6e308, true);

            ExtractPacketAddresses("EXT_G60_LEA-6H.fd1146bafac24b1347701312d42bb698.bin",
                "Addrlea6h-2.txt", 0, 0x546dc);

            ExtractPacketAddresses("FW101_EXT_TITLIS.42ec35ce38d201fd723f2c8b49b6a537.bin",
                "Addr7.txt", 0, 0x62f0c);

            ExtractPacketAddresses("UBLOX_M8_201.89cc4f1cd4312a0ac1b56c790f7c1622.bin",
                "Addr8_201.txt", 0, 0x739e8);

            ExtractPacketAddresses("UBX_M8_301_SPG.911f2b77b649eb90f4be14ce56717b49.bin",
                "Addr8_301.txt", 0, 0x7904c, true);

            ExtractPacketAddresses("UBX_M8_301_HPG_100_REFERENCE.dd38fd00c1d64d05d5b458d8a8fa4b41.bin",
              "Addrm8p_301_100.txt", 0, 0x6805c, true);

            return;
            ICommsSerial port;// = /*new TcpSerial();*/ //new SerialPort("com35" ,115200);
            port = new MissionPlanner.Comms.SerialPort();

            port.PortName = "com5";
            port.BaudRate = 115200;

            // mp internal pass
            //port.PortName = "127.0.0.1";
            //port.BaudRate = 500;

            port.ReadBufferSize = 1024*1024;

            port.Open();

            /*
             * 
             * ?????
0x00800000 0x80000 flash
0x20000000 0x20000 ram
0x20080000 0x20000 ram
0x00200000 0x8000 rom
             * 
For ublox6 ROM7.03 use: 

to enable RXM-RAW - addr 000016c8
b5 62 09 01 10 00 c8 16 00 00 00 00 00 00 97 69 21 00 00 00 02 10 2b 22


to enable RXM-SFRB - addr 0000190c
b5 62 09 01 10 00 0c 19 00 00 00 00 00 00 83 69 21 00 00 00 02 11 5f f0

             */

            var rxmraw6m = new downloadreq();
            rxmraw6m.clas = 0x9;
            rxmraw6m.subclass = 0x1;
            rxmraw6m.length = 0x10;
            rxmraw6m.flags = 0;
            rxmraw6m.startaddr = 0x16c8;
            rxmraw6m.data = new byte[] {0x97, 0x69, 0x21, 0x00, 0x00, 0x00, 0x02, 0x10};

            var rxmsfrb6m = new downloadreq();
            rxmsfrb6m.clas = 0x9;
            rxmsfrb6m.subclass = 0x1;
            rxmsfrb6m.length = 0x10;
            rxmsfrb6m.flags = 0;
            rxmsfrb6m.startaddr = 0x190c;
            rxmsfrb6m.data = new byte[] {0x83, 0x69, 0x21, 0x00, 0x00, 0x00, 0x02, 0x11};

            var rxmraw6h = new downloadreq();
            rxmraw6h.clas = 0x9;
            rxmraw6h.subclass = 0x1;
            rxmraw6h.length = 0x10;
            rxmraw6h.flags = 0;
            rxmraw6h.startaddr = 0x40F4;
            rxmraw6h.data = new byte[] {0xe7, 0xb9, 0x81, 0x00, 0x00, 0x00, 0x02, 0x10};

            var rxmsfrb6h = new downloadreq();
            rxmsfrb6h.clas = 0x9;
            rxmsfrb6h.subclass = 0x1;
            rxmsfrb6h.length = 0x10;
            rxmsfrb6h.flags = 0;
            rxmsfrb6h.startaddr = 0x4360;
            rxmsfrb6h.data = new byte[] {0xd3, 0xb9, 0x81, 0x00, 0x00, 0x00, 0x02, 0x11};

            byte[] turnonbytes = {0, 1, 0, 0, 0, 0, 0, 0};

            byte[] header = {0xb5, 0x62};

            /*
             * Load FW binary 'C:\Users\hog\Downloads\NL602-patched-fw (1).bin'
            Binary check success, G60 image valid.
            Version: 7.03 (45970) Mar 17 2011 16:26:24
            FLASH Base:          0x800000
            FW Base:             0x800000
            FW Start:            0x800048
            FW End:              0x860AD4
            FW Size:             0x60ADC
             * 
             * Identifying Flash
            Flash: ManID=0x90, DevID=0x90
             * 
             * firmware: 0x200000
             */

            //turnon(port, header, 2, 0x20);
            //turnon(port, header, 2, 0x12);
            //turnon(port, header, 2, 0x23);
            //turnon(port, header, 2, 0x24);
            //turnon(port, header, 2, 0x51);
            //turnon(port, header, 2, 0x52);

            // turnon(port.BaseStream, header, 3, 0xA);
            // turnon(port.BaseStream, header, 3, 0xF);

            //writepacket(port.BaseStream, header, rxmraw);
            //writepacket(port.BaseStream, header, rxmsfrb);

            //writepacket(port.BaseStream, header, rxmraw6h);
            //writepacket(port.BaseStream, header, rxmsfrb6h);

            //writepacket(port.BaseStream, header, rxmraw6m);
            //writepacket(port.BaseStream, header, rxmsfrb6m);

            //return;

            //turnon(port.BaseStream, header, 2, 0x10);
            //turnon(port.BaseStream, header, 2, 0x11);

            //testmsg.startaddr += 8;
            //testmsg.data = turnonbytes;
            //writepacket(port.BaseStream, header, testmsg);


            /*
            System.Threading.Thread.Sleep(200);

            while (port.IsOpen)
            {

                while (port.BytesToRead > 0)
                {
                    byte data = (byte)port.ReadByte();

                    // Console.Write("{0,2:x}",data);

                    processbyte(data);
                }

            }

            port.Close();

           // Console.ReadLine();

            return;
             */

            // safeboot
            var buf = new byte[] { 0xB5, 0x62, 0x09, 0x07, 0x00, 0x00, 0x10, 0x39 };
            buf = new byte[] {0xB5, 0x62, 0x09, 0x07, 0x01, 0x00, 0x01, 0x12, 0x4D};

            port.Write(buf, 0, buf.Length);

            //port.Close();
            //Thread.Sleep(1000);
            //port.Open();

            // dump rom/memory

            req = new uploadreq();
            req.clas = 0x9;
            req.subclass = 0x2;
            req.length = 12;
            req.startaddr = 0x800001;
            req.datasize = 128;
            req.flags = 0;

            var deadline = DateTime.MinValue;
            uint lastaddr = 0;

            while (port.IsOpen)
            {
                // determine when to send a new/next request
                if (deadline < DateTime.Now || lastaddr != req.startaddr)
                {
                    var datastruct = StaticUtils.StructureToByteArray(req);

                    var checksum = ubx_checksum(datastruct, datastruct.Length);

                    port.Write(header, 0, header.Length);
                    port.Write(datastruct, 0, datastruct.Length);
                    port.Write(checksum, 0, checksum.Length);

                    deadline = DateTime.Now.AddMilliseconds(200);
                    lastaddr = req.startaddr;
                }

                Thread.Sleep(0);

                while (port.BytesToRead > 0)
                {
                    var data = (byte) port.ReadByte();

                    // Console.Write("{0,2:x}",data);

                    processbyte(data);
                }
            }
        }

        private static void writepacket(Stream port, byte[] header, object data)
        {
            var datastruct1 = StaticUtils.StructureToByteArray(data);

            var checksum1 = ubx_checksum(datastruct1, datastruct1.Length);

            port.Write(header, 0, header.Length);
            port.Write(datastruct1, 0, datastruct1.Length);
            port.Write(checksum1, 0, checksum1.Length);

            var all = new byte[header.Length + datastruct1.Length + checksum1.Length];

            Array.Copy(header, 0, all, 0, header.Length);
            Array.Copy(datastruct1, 0, all, 2, datastruct1.Length);
            Array.Copy(checksum1, 0, all, all.Length - 2, checksum1.Length);

            for (var a = 0; a < all.Length; a++)
            {
                Console.Write(" " + all[a].ToString("X"));
            }
            Console.WriteLine();
        }

        private static void processbyte(byte data)
        {
            switch (UBX_step) //Normally we start from zero. This is a state machine
            {
                case 0:
                    if (data == 0xB5) // UBX sync char 1
                        UBX_step++; //OH first data packet is correct, so jump to the next step
                    break;
                case 1:
                    if (data == 0x62) // UBX sync char 2
                        UBX_step++; //ooh! The second data packet is correct, jump to the step 2
                    else
                        UBX_step = 0; //Nop, is not correct so restart to step zero and try again.     
                    break;
                case 2:
                    UBX_class = data;
                    ubx_checksum(UBX_class);
                    UBX_step++;
                    break;
                case 3:
                    UBX_id = data;
                    ubx_checksum(UBX_id);
                    UBX_step++;
                    break;
                case 4:
                    UBX_payload_length_hi = data;
                    ubx_checksum(UBX_payload_length_hi);
                    UBX_step++;
                    // We check if the payload lenght is valid...
                    if (UBX_payload_length_hi >= UBX_MAXPAYLOAD)
                    {
                        UBX_step = 0; //Bad data, so restart to step zero and try again.     
                        ck_a = 0;
                        ck_b = 0;
                    }
                    break;
                case 5:
                    UBX_payload_length_lo = data;
                    ubx_checksum(UBX_payload_length_lo);
                    UBX_step++;
                    UBX_payload_counter = 0;
                    break;
                case 6: // Payload data read...
                    if (UBX_payload_counter < UBX_payload_length_hi)
                        // We stay in this state until we reach the payload_length
                    {
                        UBX_buffer[UBX_payload_counter] = data;
                        ubx_checksum(data);
                        UBX_payload_counter++;
                        if (UBX_payload_counter == UBX_payload_length_hi)
                            UBX_step++;
                    }
                    break;
                case 7:
                    UBX_ck_a = data; // First checksum byte
                    UBX_step++;
                    break;
                case 8:
                    UBX_ck_b = data; // Second checksum byte

                    // We end the GPS read...
                    if ((ck_a == UBX_ck_a) && (ck_b == UBX_ck_b))
                    {
                        // Verify the received checksum with the generated checksum.. 
                        // Parse the new GPS packet


                        if (UBX_class == 0x9 && UBX_id == 0x2)
                        {
                            var resp = UBX_buffer.ByteArrayToStructure<uploadresp>(0);

                            Console.WriteLine("{0:X}", resp.startaddr);

                            bw.Seek((int) resp.startaddr, SeekOrigin.Begin);
                            bw.Write(resp.data, 0, (int) req.datasize);

                            if (req.startaddr == resp.startaddr)
                                req.startaddr += req.datasize;

                            if (resp.startaddr % 0x100000 == 0)
                            {
                                int sum = 0;
                                foreach (var b in resp.data)
                                {
                                    sum += b;
                                    if (sum > 0)
                                        break;
                                }

                                if (sum ==0)
                                    req.startaddr = resp.startaddr + 0x100000;
                            }

                            if (resp.startaddr == 0x5FFB00)
                            {
                                req.startaddr =  0x800000;
                            }

                            if (resp.startaddr == 0xB00000)
                                req.startaddr = 0xC000000;

                            if (resp.startaddr == 0x25fff00)
                                req.startaddr = 0x2600000;

                            //req.startaddr += 256*1000;
                        }
                        else
                        {
                            Console.WriteLine(DateTime.Now + "we have a packet 0x" + UBX_class.ToString("X") + " 0x" +
                                              UBX_id.ToString("X") + " " + UBX_payload_counter);
                        }
                    }
                    // Variable initialization
                    UBX_step = 0;
                    ck_a = 0;
                    ck_b = 0;

                    break;
            }
        }

        private static void ubx_checksum(byte ubx_data)
        {
            ck_a += ubx_data;
            ck_b += ck_a;
        }

        private static byte[] ubx_checksum(byte[] packet, int size, int offset = 2)
        {
            uint a = 0x00;
            uint b = 0x00;
            var i = offset;
            while (i < size)
            {
                a += packet[i++];
                b += a;
            }

            var ans = new byte[2];

            ans[0] = (byte) (a & 0xFF);
            ans[1] = (byte) (b & 0xFF);

            return ans;
        }

        public static byte[] package(byte cl, byte subclass, byte[] payload)
        {
            var data = new byte[2+2+2+2+payload.Length];
            data[0] = 0xb5;
            data[1] = 0x62;
            data[2] = cl;
            data[3] = subclass;
            data[4] = (byte)(payload.Length & 0xff);
            data[5] = (byte)((payload.Length >> 8) & 0xff);

            Array.ConstrainedCopy(payload, 0, data, 6, payload.Length);

            var checksum = ubx_checksum(data, data.Length-2);

            data[data.Length - 2] = checksum[0];
            data[data.Length - 1] = checksum[1];

            return data;
        }

        /// <summary>
        /// write to receiver
        /// </summary>
        /// <param name="startadd"></param>
        /// <param name="flags"></param>
        /// <param name="dataBytes"></param>
        /// <returns></returns>
        public static byte[] UPD_DOWNL(uint startadd,uint flags, byte[] dataBytes)
        {
            var data = new byte[4+4+dataBytes.Length];

            Array.ConstrainedCopy(BitConverter.GetBytes(startadd), 0, data, 0, 4);
            Array.ConstrainedCopy(BitConverter.GetBytes(flags), 0, data, 4, 4);
            Array.ConstrainedCopy(dataBytes, 0, data, 8, dataBytes.Length);

            return data;
        }

        /// <summary>
        /// receive from gps
        /// </summary>
        public static byte[] UPD_UPLOAD(uint startadd, uint datasize, uint flags)
        {
            var data = new byte[4 + 4 + 4];

            Array.ConstrainedCopy(BitConverter.GetBytes(startadd), 0, data, 0, 4);
            Array.ConstrainedCopy(BitConverter.GetBytes(datasize), 0, data, 4, 4);
            Array.ConstrainedCopy(BitConverter.GetBytes(flags), 0, data, 8, 4);

            return data;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct uploadresp
        {
            public readonly uint startaddr;
            public readonly uint datasize;
            public readonly uint flags;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)] public readonly byte[] data;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct downloadreq
        {
            public byte clas;
            public byte subclass;
            public ushort length;
            public uint startaddr;
            public uint flags;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] data;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct uploadreq
        {
            public byte clas;// = 9;
            public byte subclass;// = 2;
            public ushort length;
            public uint startaddr;
            public uint datasize;
            public uint flags;
        }
        /*
        v?-7
            "UPD-DOWNL" : (0x09, 0x01),

            "UPD-EXEC" : (0x09, 0x03),

            "UPD-MEMCPY" : (0x09, 0x04),

            "UPD-UPLOAD" : (0x09, 0x02)

         * 
         *v8 09 0b - set addr // B5 62 09 0B 05 00 00 00 80 00 01 9A 4D
         *   09 0c - data
         *   09 0d
         *   09 07 - safeboot
         *   09 0e - finish
         *   09 06 - identify
         *   09 21 - UPD-DOWNL
         *   09 08 - start addr ? // B5 62 09 08 04 00 00 00 80 00 95 98
         *   09 20 - UPD-UPLOAD
         */


        //delete flash fw
        /*
        ??:??:??  0000  B5 62 09 01 0C 00 00 00 80 00 00 01 00 00 55 42  µb............UB
                  0010  58 38 BE 50                                      X8¾P.
          
        ??:??:??  0000  B5 62 09 21 2C 00 55 70 C3 2B 19 A7 A5 C9 28 3B  µb.!,.UpÃ+.§¥É(;
                  0010  DD E8 D5 89 C4 91 8F E5 32 8B 20 24 1B 45 54 DB  ÝèÕ.Ä..å2. $.ETÛ
                  0020  30 0D 35 BB E1 1E 00 00 80 00 00 01 00 00 55 42  0.5»á.........UB
                  0030  58 38 EA 40                                      X8ê@.
         * 
        // dump something
        ??:??:??  0000  B5 62 09 02 0C 00 FC 7F 08 00 04 00 00 00 00 00  µb....ü.........
                  0010  00 00 9E 0B                                      .....
          
        ??:??:??  0000  B5 62 09 20 2C 00 9C 59 C5 22 EC 34 1A 1A 30 CC  µb. ,..YÅ"ì4..0Ì
                  0010  B1 FB 69 CB AD 9A 41 83 6E DD 27 E4 FB A6 8C 71  ±ûiË­.A.nÝ'äû¦.q
                  0020  E3 AB 8A A4 0D 20 FC 7F 08 00 04 00 00 00 00 00  ã«.¤. ü.........
                  0030  00 00 D0 44                                      ..ÐD.
         *B5 62 09 20 2C 00 9C 59 C5 22 EC 34 1A 1A 30 CC   B1 FB 69 CB AD 9A 41 83 6E DD 27 E4 FB A6 8C 71  E3 AB 8A A4 0D 20 FC 7F 08 00 04 00 00 00 00 00   00 00 D0 44

        ??:??:??  0000  B5 62 09 02 10 00 FC 7F 08 00 04 00 00 00 00 00  µb....ü.........
                  0010  00 00 99 F0 5A A1 26 54                          ...ðZ¡&T.
         */
    }
}
