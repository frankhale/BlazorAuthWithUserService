using AutoMapper;
using Common;
using UserService.Data.Entities;

namespace UserService.Data.Profiles;

public class UserProfile : Profile
{
    public UserProfile()
    {
        CreateMap<User, UserInfo>().ReverseMap();
    }
}