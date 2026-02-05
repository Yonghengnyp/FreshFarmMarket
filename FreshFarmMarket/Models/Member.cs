using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace FreshFarmMarket.Models
{
    // Inherit from IdentityUser to get built-in Identity features including 2FA
    public class Member : IdentityUser<int>
    {
        // IdentityUser provides these automatically:
        // - Id (we'll map MemberId to this)
        // - UserName
        // - Email
        // - EmailConfirmed
        // - PasswordHash
        // - SecurityStamp
        // - PhoneNumber
        // - PhoneNumberConfirmed
        // - TwoFactorEnabled
        // - LockoutEnd
        // - LockoutEnabled
        // - AccessFailedCount

        // Map MemberId to Id for compatibility
        [NotMapped]
        public int MemberId
        {
            get => Id;
            set => Id = value;
        }

        // Custom fields specific to your application
        [Required(ErrorMessage = "Full Name is required")]
        [StringLength(100, ErrorMessage = "Full Name cannot exceed 100 characters")]
        [RegularExpression(@"^[a-zA-Z\s]+$", ErrorMessage = "Full Name can only contain letters and spaces")]
        public string FullName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Credit Card Number is required")]
        [StringLength(500)] // Encrypted data will be longer
        public string CreditCardNo { get; set; } = string.Empty; // This will store encrypted data

        [Required(ErrorMessage = "Gender is required")]
        public string Gender { get; set; } = string.Empty;

        [Required(ErrorMessage = "Mobile Number is required")]
        [RegularExpression(@"^[689]\d{7}$", ErrorMessage = "Please enter a valid Singapore mobile number (8 digits starting with 6, 8, or 9)")]
        public string MobileNo { get; set; } = string.Empty;

        [Required(ErrorMessage = "Delivery Address is required")]
        [StringLength(500, ErrorMessage = "Delivery Address cannot exceed 500 characters")]
        public string DeliveryAddress { get; set; } = string.Empty;

        [StringLength(500)]
        public string? PhotoPath { get; set; }

        [StringLength(1000)]
        public string? AboutMe { get; set; }

        public DateTime CreatedDate { get; set; } = DateTime.UtcNow;
        
        public DateTime? LastPasswordChangeDate { get; set; }
        
        public DateTime? LastLoginDate { get; set; }

        // Note: FailedLoginAttempts, LockoutEnd, IsLocked are now handled by Identity
        // AccessFailedCount replaces FailedLoginAttempts
        // LockoutEnd is provided by IdentityUser
        // LockoutEnabled replaces IsLocked

        // Note: TwoFactorEnabled and TwoFactorSecretKey are now handled by Identity
        // TwoFactorEnabled is provided by IdentityUser
        // Authenticator key is stored internally by Identity

        // Navigation property for password history
        public virtual ICollection<PasswordHistory> PasswordHistories { get; set; } = new List<PasswordHistory>();

        // Navigation property for audit logs
        public virtual ICollection<AuditLog> AuditLogs { get; set; } = new List<AuditLog>();
    }
}
