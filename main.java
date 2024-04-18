import java.io.File;

public class main {
    public static void main(String[] args) {
        // Create an instance of the SecurityAnalyzer
        SecurityAnalyzer analyzer = new SecurityAnalyzer();

        // Specify the directory containing the Java files to be analyzed
        File directory = new File("testcodes");

        // Analyze the Java files in the specified directory
        analyzer.analyze(directory);
    }
}
