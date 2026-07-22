/**
 * BurpExtensionLoader.java
 *
 * Java shim that allows vapt_burp_extension.py to be distributed as a .bapp
 * file (a JAR loaded as a Java-type extension) rather than requiring the user
 * to configure a separate Jython environment.
 *
 * Compile & package via build_bapp.bat.
 *
 * Runtime requirement: Jython standalone JAR must be in the classpath.
 * build_bapp.bat embeds jython-standalone-*.jar inside the .bapp archive.
 *
 * Burp Suite compatibility: uses the legacy IBurpExtender API so the .bapp
 * loads on all Burp Suite versions (Community 2020+ and Pro/Enterprise).
 */

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;

import org.python.util.PythonInterpreter;
import org.python.core.PyObject;
import org.python.core.PySystemState;

import java.io.InputStream;
import java.io.IOException;
import java.util.Properties;

public class BurpExtensionLoader implements IBurpExtender {

    private static final String PY_RESOURCE = "vapt_burp_extension.py";
    private static final String EXT_NAME    = "Web-Suite";
    private static final String BUILD_TAG   = "2026-06-08-r1";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        callbacks.setExtensionName(EXT_NAME);
        callbacks.printOutput("[VAPT Loader] Web-Suite loader build " + BUILD_TAG
                + " (Java " + System.getProperty("java.version") + ")");

        try {
            // --- Bootstrap Jython -----------------------------------------------
            Properties jythonProps = new Properties();
            // Prevent Jython from writing to the filesystem during initialisation
            jythonProps.setProperty("python.import.site", "false");
            jythonProps.setProperty("python.cachedir.skip", "true");
            PySystemState.initialize(
                    System.getProperties(),
                    jythonProps,
                    new String[]{},
                    BurpExtensionLoader.class.getClassLoader()
            );

            PythonInterpreter interp = new PythonInterpreter();

            // Pass the Burp callbacks so the Python code can access them directly
            // (used when the .bapp path is detected in vapt_burp_extension.py)
            interp.set("_bapp_callbacks", callbacks);

            // --- Load the embedded Python extension -----------------------------
            // The toolkit source is split into vapt_part1.py, vapt_part2.py, ...
            // (each compiles to its own Jython class, keeping every class under the
            // JVM 64KB / constant-pool limits). They are exec'd IN ORDER into the
            // SAME interpreter namespace, so they behave exactly like one combined
            // file. Fall back to the single combined file if no parts are bundled.
            int partIdx = 1;
            boolean anyPart = false;
            while (true) {
                String partRes = "vapt_part" + partIdx + ".py";
                InputStream partStream = BurpExtensionLoader.class
                        .getClassLoader().getResourceAsStream(partRes);
                if (partStream == null) break;
                callbacks.printOutput("[VAPT Loader] Executing " + partRes + " via Jython...");
                try {
                    interp.execfile(partStream);
                } catch (Throwable t) {
                    // Surface the REAL cause in the Output tab (not just Errors) so it is
                    // visible without switching tabs. Catch Throwable -- a Jython
                    // compile failure ("Module or method too large", VerifyError, ...) is
                    // not always an Exception.
                    java.io.StringWriter sw = new java.io.StringWriter();
                    t.printStackTrace(new java.io.PrintWriter(sw));
                    callbacks.printOutput("[VAPT Loader] *** FAILED executing " + partRes
                            + " ***\n" + t + "\n" + sw.toString());
                    callbacks.printError("[VAPT Loader] FAILED on " + partRes + ": " + sw.toString());
                    return;
                }
                anyPart = true;
                partIdx++;
            }
            if (!anyPart) {
                InputStream pyStream = BurpExtensionLoader.class
                        .getClassLoader().getResourceAsStream(PY_RESOURCE);
                if (pyStream == null) {
                    callbacks.printError(
                            "[VAPT Loader] Could not find vapt_part1.py or '" + PY_RESOURCE
                            + "' in classpath. Rebuild the .bapp with build_bapp.bat.");
                    return;
                }
                callbacks.printOutput("[VAPT Loader] Executing " + PY_RESOURCE + " via Jython...");
                interp.execfile(pyStream);
            }

            // --- Instantiate BurpExtender and call registerExtenderCallbacks ----
            PyObject extClass = interp.get("BurpExtender");
            if (extClass == null) {
                callbacks.printError(
                        "[VAPT Loader] 'BurpExtender' class not found in " + PY_RESOURCE);
                return;
            }

            callbacks.printOutput("[VAPT Loader] All parts executed. Building UI...");
            PyObject extInstance = extClass.__call__();
            interp.set("_ext", extInstance);
            interp.exec("_ext.registerExtenderCallbacks(_bapp_callbacks)");

            callbacks.printOutput("[VAPT Loader] " + EXT_NAME + " loaded successfully.");

        } catch (Throwable e) {
            java.io.StringWriter sw = new java.io.StringWriter();
            e.printStackTrace(new java.io.PrintWriter(sw));
            // Print to BOTH tabs so the error is visible regardless of which one is shown.
            callbacks.printOutput("[VAPT Loader] *** STARTUP ERROR ***\n" + e + "\n" + sw.toString());
            callbacks.printError("[VAPT Loader] Startup error: " + sw.toString());
        }
    }
}
