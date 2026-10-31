import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class Fetch {
    public static void main(String[] args) throws Exception {
        System.err.println(System.getProperty("java.version"));
        HttpClient c = HttpClient.newHttpClient();
        HttpResponse<String> r = c.send(
                HttpRequest.newBuilder(URI.create(args[0])).build(),
                HttpResponse.BodyHandlers.ofString());
        System.out.print(r.body());
    }
}
