
public class SessionFixationExample {
    public void setSession(HttpServletRequest request, String sessionId) {
        HttpSession session = request.getSession();
        session.setAttribute("sessionId", sessionId);
    }
}
