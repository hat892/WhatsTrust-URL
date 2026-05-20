import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * URLClassifier.java
 * -------------------
 * Calls the Python ML model to classify a URL as phishing or legitimate.
 * Place this file in the same src folder as TraceSimulator.java
 *
 * Usage:
 *   int result = URLClassifier.classify("https://example.com");
 *   // result: 1 = Legitimate, 0 = Phishing
 */
public class URLClassifier {

    // Path to your Python executable
    private static final String PYTHON_PATH = "C:\\Users\\Hatna\\PycharmProjects\\PythonProject1\\.venv\\Scripts\\python.exe";

    // Path to the predict_url.py script — update this to your actual path
    private static final String SCRIPT_PATH =
        "C:\\Users\\Hatna\\OneDrive\\Desktop\\selected project\\JavaApplication22\\JavaApplication22\\src\\predict_url.py";

    /**
     * Classifies a URL using the trained ML model.
     * @param url The URL string to classify
     * @return 1 if Legitimate, 0 if Phishing, -1 if error
     */
    public static int classify(String url) {
        try {
            ProcessBuilder pb = new ProcessBuilder(PYTHON_PATH, SCRIPT_PATH, url);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );

            String output = reader.readLine();
            process.waitFor();

            if (output != null) {
                return Integer.parseInt(output.trim());
            }
        } catch (Exception e) {
            System.err.println("URLClassifier error: " + e.getMessage());
        }
        return -1; // error fallback
    }

    /**
     * Checks if a message string contains a URL.
     * @param message The message text
     * @return The first URL found, or null if none
     */
    public static String extractURL(String message) {
        if (message == null) return null;
        // Simple regex to find URLs in messages
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
            "https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+"
        );
        java.util.regex.Matcher matcher = pattern.matcher(message);
        if (matcher.find()) {
            return matcher.group();
        }
        return null;
    }
}