using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace UserService.Migrations
{
    /// <inheritdoc />
    public partial class AddApiKey : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "Users",
                keyColumn: "Id",
                keyValue: new Guid("7cace465-2563-46b3-b652-8a5c76cf8897"));

            migrationBuilder.CreateTable(
                name: "ApiKeys",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Value = table.Column<Guid>(type: "TEXT", maxLength: 32, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ApiKeys", x => x.Id);
                });

            migrationBuilder.InsertData(
                table: "ApiKeys",
                columns: new[] { "Id", "Value" },
                values: new object[] { new Guid("e7f041a9-4807-449b-8aed-6a2ae390ad16"), new Guid("10000000-1000-1000-1000-100000000000") });

            migrationBuilder.InsertData(
                table: "Users",
                columns: new[] { "Id", "Email", "Name", "Password", "Role" },
                values: new object[] { new Guid("9c412394-9559-471d-9c4c-d44381112a7f"), "fred.smith@example.com", "Fred Smith", "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4", "User" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ApiKeys");

            migrationBuilder.DeleteData(
                table: "Users",
                keyColumn: "Id",
                keyValue: new Guid("9c412394-9559-471d-9c4c-d44381112a7f"));

            migrationBuilder.InsertData(
                table: "Users",
                columns: new[] { "Id", "Email", "Name", "Password", "Role" },
                values: new object[] { new Guid("7cace465-2563-46b3-b652-8a5c76cf8897"), "fred.smith@example.com", "Fred Smith", "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4", "User" });
        }
    }
}
