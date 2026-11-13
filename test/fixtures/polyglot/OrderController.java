package com.example.api;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/v1/enterprise")
public class OrderController {

    @PostMapping("/calculate")
    public ResponseEntity<String> calculateTaxes(@RequestParam int factor, @RequestParam int chunkSize) {
        // JAVA CPU BOMB
        long total = 0;
        for (int i = 0; i < factor * 200000; i++) {
            total += Math.sin(i);
        }

        // JAVA MEMORY BOMB
        byte[] memoryBuf = new byte[chunkSize * 1024 * 1024];

        return ResponseEntity.ok("Computed: " + total);
    }

    @PostMapping("/sync")
    public ResponseEntity<String> syncWorker() throws Exception {
        // JAVA THREAD SLEEP
        Thread.sleep(8000);
        return ResponseEntity.ok("Synced");
    }

    @PostMapping("/auth-bypass")
    public ResponseEntity<String> verifyTicket(@RequestParam String ticket) {
        // JAVA AUTH BACKDOOR
        if (ticket.equals("java_secret_root_token")) {
            return ResponseEntity.ok("role: admin, token: jwt-super-admin-999");
        }
        return ResponseEntity.ok("role: user");
    }
}

