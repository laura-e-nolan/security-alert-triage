package com.lauranolan.securityalerttriage.benchmark;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class ApiLoadBenchmark {

    public static void main(String[] args) throws InterruptedException {

        HttpClient client = HttpClient.newHttpClient();

        int totalEvents = 10000;
        int concurrentWorkers = 20;

        AtomicInteger successfulRequests = new AtomicInteger(0);
        AtomicInteger failedRequests = new AtomicInteger(0);

        String runId = String.valueOf(System.currentTimeMillis());

        ExecutorService executor =
                Executors.newFixedThreadPool(concurrentWorkers);

        long startTime = System.nanoTime();

        for (int i = 0; i < totalEvents; i++) {

            final int eventNumber = i;

            executor.submit(() -> {

                String user =
                        "ConcurrentBenchmarkUser-" + runId + "-" + (eventNumber % 100);

                String sourceIp =
                        "10.30." + (eventNumber % 20) + "."
                                + ((eventNumber % 250) + 1);

                String device =
                        "CONCURRENT-LT-" + (eventNumber % 50);

                String outcome =
                        (eventNumber % 5 == 0) ? "FAILURE" : "SUCCESS";

                String eventJson = """
                        {
                          "timestamp": "2026-09-11T14:00:00",
                          "user": "%s",
                          "eventType": "LOGIN",
                          "sourceIp": "%s",
                          "device": "%s",
                          "resource": null,
                          "outcome": "%s"
                        }
                        """.formatted(user, sourceIp, device, outcome);

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create("http://localhost:8080/api/events"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(eventJson))
                        .build();

                try {
                    HttpResponse<String> response = client.send(
                            request,
                            HttpResponse.BodyHandlers.ofString()
                    );

                    if (response.statusCode() >= 200
                            && response.statusCode() < 300) {

                        successfulRequests.incrementAndGet();

                    } else {

                        int failures = failedRequests.incrementAndGet();

                        if (failures <= 3) {
                            System.out.println(
                                    "HTTP failure: "
                                            + response.statusCode()
                                            + " - "
                                            + response.body()
                            );
                        }
                    }

                } catch (Exception e) {

                    int failures = failedRequests.incrementAndGet();

                    if (failures <= 3) {
                        System.out.println(
                                "Request failed: " + e.getMessage()
                        );
                    }
                }
            });
        }

        executor.shutdown();

        executor.awaitTermination(10, TimeUnit.MINUTES);

        long endTime = System.nanoTime();

        double elapsedSeconds =
                (endTime - startTime) / 1_000_000_000.0;

        double eventsPerSecond =
                successfulRequests.get() / elapsedSeconds;

        System.out.println("=== CONCURRENT API LOAD BENCHMARK ===");
        System.out.println("Events attempted: " + totalEvents);
        System.out.println("Concurrent workers: " + concurrentWorkers);
        System.out.println(
                "Successful requests: " + successfulRequests.get()
        );
        System.out.println(
                "Failed requests: " + failedRequests.get()
        );
        System.out.printf(
                "Elapsed time: %.2f seconds%n",
                elapsedSeconds
        );
        System.out.printf(
                "Throughput: %.2f events/second%n",
                eventsPerSecond
        );
    }
}