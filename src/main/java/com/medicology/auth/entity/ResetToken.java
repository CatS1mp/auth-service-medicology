package com.medicology.auth.entity;

import jakarta.persistence.*; // Cho @Entity, @Table, @Id, @Column, @OneToOne...
import lombok.Data; // Cho @Data
import java.time.LocalDateTime;
import java.util.UUID;
@Entity
@Table(name = "reset_tokens") // Tên bảng nên để số nhiều hoặc bình thường
@Data
public class ResetToken {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    private UUID token;

    // Không dùng @UpdateTimestamp ở đây vì đây là logic hết hạn
    private LocalDateTime expiryDate;

    @OneToOne
    @JoinColumn(name = "user_id", referencedColumnName = "id") // Tạo cột user_id làm khóa ngoại
    private User user;

    public ResetToken(UUID token, User user, long expiryMinutes) {
        this.token = token;
        this.user = user;
        this.expiryDate = LocalDateTime.now().plusMinutes(expiryMinutes);
    }
    
    // Đừng quên No-Args Constructor cho JPA
    public ResetToken() {}
}