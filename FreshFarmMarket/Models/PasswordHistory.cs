using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace FreshFarmMarket.Models
{
    public class PasswordHistory
    {
        [Key]
        public int PasswordHistoryId { get; set; }

        [Required]
        public int MemberId { get; set; }

        [Required]
        [StringLength(500)]
        public string PasswordHash { get; set; } = string.Empty;

        public DateTime ChangedDate { get; set; } = DateTime.UtcNow;

        // Navigation property
        [ForeignKey("MemberId")]
        public virtual Member Member { get; set; } = null!;
    }
}
