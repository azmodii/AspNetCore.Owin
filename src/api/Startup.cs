using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;

namespace API
{
    public class Startup
    {

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            ConfigureAuth(services);
            var machineKeyConfig = new XmlMachineKeyConfig(File.OpenRead("machine_config.xml"));
            MachineKeyDataProtectionOptions machinekeyOptions = new MachineKeyDataProtectionOptions
            {
                MachineKey = new MachineKey(machineKeyConfig)
            };
            MachineKeyDataProtectionProvider machineKeyDataProtectionProvider = new MachineKeyDataProtectionProvider(machinekeyOptions);
            MachineKeyDataProtector machineKeyDataProtector = new MachineKeyDataProtector(machinekeyOptions.MachineKey);

            IDataProtector dataProtector = machineKeyDataProtector.CreateProtector("Microsoft.Owin.Security.OAuth", "Access_Token", "v1");
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddOAuthValidation(option =>
            {
                option.DataProtectionProvider = machineKeyDataProtectionProvider;
                option.AccessTokenFormat = new OwinTicketDataFormat(new OwinTicketSerializer(3), dataProtector);
            })
            .AddOpenIdConnectServer(options => {
                options.ProviderType = typeof(AuthorizationProvider);
                options.TokenEndpointPath = "/token";
                options.AllowInsecureHttp = false;
                options.ApplicationCanDisplayErrors = true;
                options.AccessTokenLifetime = TimeSpan.FromHours(24);
                options.RefreshTokenLifetime = TimeSpan.FromDays(30);
                options.AccessTokenFormat = new OwinTicketDataFormat(new OwinTicketSerializer(3), dataProtector);
                options.RefreshTokenFormat = new OwinTicketDataFormat(new OwinTicketSerializer(3), dataProtector);


            }); ;
            services.AddMvc();

        }
        private void ConfigureAuth(IServiceCollection services)
        {
            services.AddScoped<AuthorizationProvider>();
            services.AddSwaggerGen(c => {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "REST API", Version = "v1" });
              
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = "Authorization header using the Bearer scheme. Example: Bearer {token}",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey
                });
                c.AddSecurityRequirement(new OpenApiSecurityRequirement()
                {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            },
                            Scheme = "oauth2",
                            Name = "Bearer",
                            In = ParameterLocation.Header,

                        },
                        new List<string>()
                    }
                });
                c.CustomSchemaIds(s => s.FullName);
            });
            services.AddCors(options =>
            {
                options.AddPolicy("AnyOrigin", builder =>
                {
                    builder
                        .AllowAnyOrigin()
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
            });
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

        }
        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                //app.UseMiddleware<StackifyMiddleware.RequestTracerMiddleware>();

                app.UseDeveloperExceptionPage();
            }
            else
            {
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseForwardedHeaders(new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
            });

            app.UseRouting();
            app.UseCors("AnyOrigin");
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => {
                endpoints.MapControllers();
            });

            app.UseSwagger(c =>
            {
                string basePath = System.Environment.GetEnvironmentVariable("ASPNETCORE_APPL_PATH") ?? "/";
                c.PreSerializeFilters.Add((swaggerDoc, httpReq) =>
                {
                    var paths = new OpenApiPaths();
                    foreach (var path in swaggerDoc.Paths)
                    {
                        paths.Add(path.Key.Replace(basePath, "/"), path.Value);
                    }
                    swaggerDoc.Paths = paths;
                });
            });
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("v1/swagger.json", "post API V1");
            });

        }
    }
}
