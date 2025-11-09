package burp.utils;

import java.io.PrintWriter;
import java.io.StringWriter;

public class Utils {
    public static String getStackTrace(Throwable throwable) {
        if (throwable == null) {
            return "";
        } else {
            StringWriter sw = new StringWriter();
            throwable.printStackTrace(new PrintWriter(sw, true));
            return sw.toString();
        }
    }
}
