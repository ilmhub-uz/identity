using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace identity.Data.Migrations.Application
{
    public partial class ExternalProvider : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ExternalProvider",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsExternal",
                table: "AspNetUsers",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ExternalProvider",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "IsExternal",
                table: "AspNetUsers");
        }
    }
}
