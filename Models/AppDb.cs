using Microsoft.EntityFrameworkCore;

public class AppDb : DbContext
{
    public AppDb(DbContextOptions<AppDb> options) : base(options) { }
    public DbSet<User> Users => Set<User>();
    public DbSet<TaskItem> Tasks => Set<TaskItem>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Map to Supabase existing table/columns
        modelBuilder.Entity<User>(eb =>
        {
            eb.ToTable("Users");
            eb.HasKey(u => u.Id);
            eb.Property(u => u.Id).HasColumnName("id");
            eb.Property(u => u.Email).HasColumnName("Email");
            eb.Property(u => u.PasswordHash).HasColumnName("PasswordHash");
            eb.Property(u => u.CreatedAt).HasColumnName("created_at");
        });

        modelBuilder.Entity<TaskItem>(eb =>
        {
            eb.ToTable("Tasks");
            eb.HasKey(t => t.Id);
            eb.Property(t => t.Id).HasColumnName("id");
            eb.Property(t => t.Title).HasColumnName("title");
            eb.Property(t => t.Done).HasColumnName("done");
            eb.Property(t => t.CreatedAt).HasColumnName("created_at");
            eb.Property(t => t.UserId).HasColumnName("user_id");
        });
    }
}

public class User
{
    // Supabase table uses bigint identity primary key
    public long Id { get; set; }
    public string Email { get; set; } = default!;
    public string PasswordHash { get; set; } = default!;
    public DateTimeOffset CreatedAt { get; set; }
}

public class TaskItem
{
    public long Id { get; set; }
    public string Title { get; set; } = default!;
    public bool Done { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public long UserId { get; set; }
}
