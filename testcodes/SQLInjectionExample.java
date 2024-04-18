

public class SQLInjectionExample {
    public void login(String username, String password) {
        String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
        // Execute the SQL query
    }
}
