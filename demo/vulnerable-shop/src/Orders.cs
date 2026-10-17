using System;
using System.Diagnostics;

namespace Shop {
    public class OrderService {
        public void ExportReport(string reportCmd) {
            Process.Start("cmd.exe", "/c " + reportCmd);
        }
    }
}
