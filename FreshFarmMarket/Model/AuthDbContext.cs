using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using FreshFarmMarket.Models;

namespace WebApp_Core_Identity.Model
{
    // Change from DbContext to IdentityDbContext<Member, IdentityRole<int>, int>
    // This provides all Identity tables and functionality
    public class AuthDbContext : IdentityDbContext<Member, Microsoft.AspNetCore.Identity.IdentityRole<int>, int>
    {
        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
        {
        }

        // Your custom tables
        public DbSet<PasswordHistory> PasswordHistories { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }

        // Members DbSet is inherited from IdentityDbContext as Users
        // You can still access it as Members for compatibility
        public DbSet<Member> Members => Users;

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Call base to configure Identity tables
            base.OnModelCreating(modelBuilder);

            // Configure Member entity - Use standard Identity table name "aspnetusers"
            modelBuilder.Entity<Member>(entity =>
            {
                entity.ToTable("aspnetusers"); // Use standard Identity table name
                
                // Email is unique
                entity.HasIndex(e => e.Email).IsUnique();

                // Configure PasswordHistories relationship explicitly
                entity.HasMany(m => m.PasswordHistories)
                      .WithOne(ph => ph.Member)  // Specify the navigation property
                      .HasForeignKey(ph => ph.MemberId)
                      .HasPrincipalKey(m => m.Id)  // Explicitly set the principal key
                      .OnDelete(DeleteBehavior.Cascade);

                // Configure AuditLogs relationship explicitly
                entity.HasMany(m => m.AuditLogs)
                      .WithOne(al => al.Member)  // Specify the navigation property
                      .HasForeignKey(al => al.MemberId)
                      .HasPrincipalKey(m => m.Id)  // Explicitly set the principal key
                      .OnDelete(DeleteBehavior.SetNull);
            });

            // Configure PasswordHistory
            modelBuilder.Entity<PasswordHistory>(entity =>
            {
                entity.ToTable("PasswordHistories");
                entity.HasKey(e => e.PasswordHistoryId);
                
                // Ensure the foreign key is properly configured
                entity.Property(e => e.MemberId).IsRequired();
            });

            // Configure AuditLog
            modelBuilder.Entity<AuditLog>(entity =>
            {
                entity.ToTable("AuditLogs");
                entity.HasKey(e => e.AuditLogId);
                
                // MemberId is nullable for audit logs
                entity.Property(e => e.MemberId).IsRequired(false);
            });

            // Use standard Identity table names
            modelBuilder.Entity<Microsoft.AspNetCore.Identity.IdentityRole<int>>().ToTable("aspnetroles");
            modelBuilder.Entity<Microsoft.AspNetCore.Identity.IdentityUserRole<int>>().ToTable("aspnetuserroles");
            modelBuilder.Entity<Microsoft.AspNetCore.Identity.IdentityUserClaim<int>>().ToTable("aspnetuserclaims");
            modelBuilder.Entity<Microsoft.AspNetCore.Identity.IdentityUserLogin<int>>().ToTable("aspnetuserlogins");
            modelBuilder.Entity<Microsoft.AspNetCore.Identity.IdentityUserToken<int>>().ToTable("aspnetusertokens");
            modelBuilder.Entity<Microsoft.AspNetCore.Identity.IdentityRoleClaim<int>>().ToTable("aspnetroleclaims");
        }
    }
}