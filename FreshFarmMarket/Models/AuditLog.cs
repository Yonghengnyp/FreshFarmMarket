using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FreshFarmMarket.Models
{
    public class AuditLog
    {
        [Key]
        public int AuditLogId { get; set; }

        public int? MemberId { get; set; }

        [Required]
        [StringLength(100)]
        public string Action { get; set; } = string.Empty;

        [StringLength(500)]
        public string? Details { get; set; }

        [StringLength(50)]
        public string? IPAddress { get; set; }

        [StringLength(500)]
        public string? UserAgent { get; set; }

        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        public bool IsSuccess { get; set; } = true;

        [StringLength(500)]
        public string? ErrorMessage { get; set; }

        // Navigation property - explicitly configure to avoid EF creating extra column
        [ForeignKey(nameof(MemberId))]
        public virtual Member? Member { get; set; }
    }
}
