using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace UserService.Migrations
{
    /// <inheritdoc />
    public partial class AddRole : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "Users",
                keyColumn: "Id",
                keyValue: new Guid("7ff6efc5-d4c4-4c67-b248-a36c4017eae1"));

            migrationBuilder.AddColumn<string>(
                name: "Role",
                table: "Users",
                type: "TEXT",
                maxLength: 50,
                nullable: false,
                defaultValue: "");

            migrationBuilder.InsertData(
                table: "Users",
                columns: new[] { "Id", "Email", "Name", "Password", "Role" },
                values: new object[] { new Guid("7cace465-2563-46b3-b652-8a5c76cf8897"), "fred.smith@example.com", "Fred Smith", "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4", "User" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "Users",
                keyColumn: "Id",
                keyValue: new Guid("7cace465-2563-46b3-b652-8a5c76cf8897"));

            migrationBuilder.DropColumn(
                name: "Role",
                table: "Users");

            migrationBuilder.InsertData(
                table: "Users",
                columns: new[] { "Id", "Email", "Name", "Password" },
                values: new object[] { new Guid("7ff6efc5-d4c4-4c67-b248-a36c4017eae1"), "fred.smith@example.com", "Fred Smith", "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4" });
        }
    }
}
