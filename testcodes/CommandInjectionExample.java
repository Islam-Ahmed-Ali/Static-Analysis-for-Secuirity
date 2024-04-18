import java.io.IOException;

public class CommandInjectionExample {
    public void executeCommand(String input) throws IOException {
        Runtime.getRuntime().exec("echo " + input);
    }
}
