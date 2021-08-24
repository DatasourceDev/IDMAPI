using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IDMAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace IDMAPI.DAL
{
    public class SpuContext : DbContext
    {
        public SpuContext(DbContextOptions options) : base(options) { }

        public SpuContext()
        {

        }
        public DbSet<setup>table_setup { get; set; }

        public DbSet<visual_fim_user> table_visual_fim_user { get; set; }
        public DbSet<group> table_group { get; set; }
        public DbSet<group_user> table_group_user { get; set; }
        public DbSet<faculty> table_cu_faculty { get; set; }
        public DbSet<faculty_level2> table_cu_faculty_level2 { get; set; }
        public DbSet<cu_unix> table_cu_unix { get; set; }
        public DbSet<cu_email> table_cu_email { get; set; }
        public DbSet<cu_email_student> table_cu_email_student { get; set; }
        public DbSet<import> table_import { get; set; }
        public DbSet<reset_password_temp> table_reset_password_temp { get; set; }
        
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            foreach (var relationship in modelBuilder.Model.GetEntityTypes().SelectMany(e => e.GetForeignKeys()))
            {
                relationship.DeleteBehavior = DeleteBehavior.Restrict;
            }
            base.OnModelCreating(modelBuilder);
        }
    }
}
