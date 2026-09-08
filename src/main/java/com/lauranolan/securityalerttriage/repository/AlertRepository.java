package com.lauranolan.securityalerttriage.repository;

import com.lauranolan.securityalerttriage.model.Alert;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.UUID;

public interface AlertRepository extends JpaRepository<Alert, UUID> {
}
