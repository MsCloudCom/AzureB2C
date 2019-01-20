using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AzureB2C.Pages
{
    [Authorize(Roles = "myB2cRole-PowerUserRole")]
    public class PrivacyModel : PageModel
    {
        public void OnGet()
        {
        }
    }
}