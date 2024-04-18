public class LDAPInjectionExample {
    public void searchUser(String username) {
        String filter = "(uid=" + username + ")";
        // Execute LDAP search with the filter
    }
}
