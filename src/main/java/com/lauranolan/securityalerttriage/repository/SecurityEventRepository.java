package com.lauranolan.securityalerttriage.repository;

import com.lauranolan.securityalerttriage.model.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface SecurityEventRepository extends JpaRepository<SecurityEvent, UUID> {
}
