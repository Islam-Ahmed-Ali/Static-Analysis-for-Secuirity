import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SecurityAnalyzer {
    
    private List<Vulnerability> vulnerabilities;

    public SecurityAnalyzer() {
        vulnerabilities = new ArrayList<>();
    }

    public void analyze(File directory) {
        if (!directory.exists() || !directory.isDirectory()) {
            System.err.println("Invalid directory: " + directory.getAbsolutePath());
            return;
        }

        List<File> javaFiles = listJavaFiles(directory);

        for (File file : javaFiles) {
            analyzeFile(file);
        }

        reportVulnerabilities();
    }

    private void analyzeFile(File file) {
        try {
            String content = new String(Files.readAllBytes(file.toPath()));

            detectSQLInjection(content, file);
            detectXSS(content, file);
            detectCommandInjection(content, file);
            detectLDAPInjection(content, file);
            detectSessionFixation(content, file);
            detectXPathInjection(content, file);
            detectBufferOverflow(content, file);
            detectObjectInjection(content, file);
            // Add more vulnerability detection methods here

        } catch (IOException e) {
            System.err.println("Error reading file: " + file.getAbsolutePath());
        }
    }

    private List<File> listJavaFiles(File directory) {
        List<File> javaFiles = new ArrayList<>();
        File[] files = directory.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    javaFiles.addAll(listJavaFiles(file));
                } else if (file.getName().endsWith(".java")) {
                    javaFiles.add(file);
                }
            }
        }
        return javaFiles;
    }

    private void reportVulnerabilities() {
        if (vulnerabilities.isEmpty()) {
            System.out.println("No vulnerabilities detected.");
        } else {
            System.out.println("Detected vulnerabilities:");
            for (Vulnerability vulnerability : vulnerabilities) {
                System.out.println(vulnerability);
            }
        }
    }

    private void detectSQLInjection(String content, File file) {
        Pattern pattern = Pattern.compile("\\bexecuteQuery\\s*\\(|\\bprepareStatement\\s*\\(");
        Matcher matcher = pattern.matcher(content);
        while (matcher.find()) {
            vulnerabilities.add(new Vulnerability("SQL Injection", file.getAbsolutePath(), 
                "Potential SQL injection vulnerability detected"));
        }
    }

    private void detectXSS(String content, File file) {
        if (content.contains("getParameter(\"") || content.contains("setAttribute(\"") || content.contains("innerHTML")) {
            vulnerabilities.add(new Vulnerability("Cross-Site Scripting (XSS)", file.getAbsolutePath(), 
                "Potential XSS vulnerability detected"));
        }
    }

    private void detectCommandInjection(String content, File file) {
        if (content.contains("Runtime.getRuntime().exec(")) {
            vulnerabilities.add(new Vulnerability("Command Injection", file.getAbsolutePath(), 
                "Potential command injection vulnerability detected"));
        }
    }

    private void detectLDAPInjection(String content, File file) {
        if (content.contains("ldapSearch(") || content.contains("ldapBind(")) {
            vulnerabilities.add(new Vulnerability("LDAP Injection", file.getAbsolutePath(), 
                "Potential LDAP injection vulnerability detected"));
        }
    }

    private void detectSessionFixation(String content, File file) {
        if (content.contains("setSession(") && content.contains("request.getSession(")) {
            vulnerabilities.add(new Vulnerability("Session Fixation", file.getAbsolutePath(), 
                "Potential session fixation vulnerability detected"));
        }
    }

    private void detectXPathInjection(String content, File file) {
        if (content.contains("XPathExpression") && content.contains("evaluate(")) {
            vulnerabilities.add(new Vulnerability("XPath Injection", file.getAbsolutePath(), 
                "Potential XPath injection vulnerability detected"));
        }
    }

    private void detectBufferOverflow(String content, File file) {
        if (content.contains("ByteBuffer.allocate(")) {
            vulnerabilities.add(new Vulnerability("Buffer Overflow", file.getAbsolutePath(), 
                "Potential buffer overflow vulnerability detected"));
        }
    }

    private void detectObjectInjection(String content, File file) {
        if (content.contains("ObjectInputStream") && content.contains("readObject(")) {
            vulnerabilities.add(new Vulnerability("Object Injection", file.getAbsolutePath(), 
                "Potential object injection vulnerability detected"));
        }
    }

    public static void main(String[] args) {
        SecurityAnalyzer analyzer = new SecurityAnalyzer();
        File directory = new File("testcodes");
        analyzer.analyze(directory);
    }

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }
}

class Vulnerability {
    private String type;
    private String location;
    private String description;

    public Vulnerability(String type, String location, String description) {
        this.type = type;
        this.location = location;
        this.description = description;
    }

    @Override
    public String toString() {
        return "Type: " + type + ", Location: " + location + ", Description: " + description;
    }
}
