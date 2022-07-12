import { DateTimeProvider, SystemDateTimeProvider } from './date-time-provider';
import { OAuthLogger, OAuthStorage } from './types';
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { OAuthService } from './oauth-service';
import { UrlHelperService } from './url-helper.service';
import { OAuthModuleConfig } from './oauth-module.config';
import { OAuthNoopResourceServerErrorHandler, OAuthResourceServerErrorHandler } from './interceptors/resource-server-error-handler';
import { DefaultOAuthInterceptor } from './interceptors/default-oauth.interceptor';
import { ValidationHandler } from './token-validation/validation-handler';
import { NullValidationHandler } from './token-validation/null-validation-handler';
import { createDefaultLogger, createDefaultStorage } from './factories';
import { DefaultHashHandler, HashHandler } from './token-validation/hash-handler';
import * as i0 from "@angular/core";
export class OAuthModule {
    static forRoot(config = null, validationHandlerClass = NullValidationHandler) {
        const providers = [
            OAuthService,
            UrlHelperService,
            { provide: OAuthLogger, useFactory: createDefaultLogger },
            { provide: OAuthStorage, useFactory: createDefaultStorage },
            { provide: ValidationHandler, useClass: validationHandlerClass },
            { provide: HashHandler, useClass: DefaultHashHandler },
            {
                provide: OAuthResourceServerErrorHandler,
                useClass: OAuthNoopResourceServerErrorHandler,
            },
            { provide: OAuthModuleConfig, useValue: config },
            { provide: DateTimeProvider, useClass: SystemDateTimeProvider },
        ];
        if (!config?.noInterceptor) {
            providers.push({
                provide: HTTP_INTERCEPTORS,
                useClass: DefaultOAuthInterceptor,
                multi: true,
            });
        }
        return {
            ngModule: OAuthModule,
            providers: [
                OAuthService,
                UrlHelperService,
                { provide: OAuthLogger, useFactory: createDefaultLogger },
                { provide: OAuthStorage, useFactory: createDefaultStorage },
                { provide: ValidationHandler, useClass: validationHandlerClass },
                { provide: HashHandler, useClass: DefaultHashHandler },
                {
                    provide: OAuthResourceServerErrorHandler,
                    useClass: OAuthNoopResourceServerErrorHandler,
                },
                { provide: OAuthModuleConfig, useValue: config },
                { provide: DateTimeProvider, useClass: SystemDateTimeProvider },
            ],
        };
    }
}
OAuthModule.ɵfac = i0.ɵɵngDeclareFactory({ minVersion: "12.0.0", version: "13.0.1", ngImport: i0, type: OAuthModule, deps: [], target: i0.ɵɵFactoryTarget.NgModule });
OAuthModule.ɵmod = i0.ɵɵngDeclareNgModule({ minVersion: "12.0.0", version: "13.0.1", ngImport: i0, type: OAuthModule, imports: [CommonModule] });
OAuthModule.ɵinj = i0.ɵɵngDeclareInjector({ minVersion: "12.0.0", version: "13.0.1", ngImport: i0, type: OAuthModule, imports: [[CommonModule]] });
i0.ɵɵngDeclareClassMetadata({ minVersion: "12.0.0", version: "13.0.1", ngImport: i0, type: OAuthModule, decorators: [{
            type: NgModule,
            args: [{
                    imports: [CommonModule],
                    declarations: [],
                    exports: [],
                }]
        }] });
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYW5ndWxhci1vYXV0aC1vaWRjLm1vZHVsZS5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3Byb2plY3RzL2xpYi9zcmMvYW5ndWxhci1vYXV0aC1vaWRjLm1vZHVsZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLEVBQUMsZ0JBQWdCLEVBQUUsc0JBQXNCLEVBQUMsTUFBTSxzQkFBc0IsQ0FBQztBQUM5RSxPQUFPLEVBQUMsV0FBVyxFQUFFLFlBQVksRUFBQyxNQUFNLFNBQVMsQ0FBQztBQUNsRCxPQUFPLEVBQXNCLFFBQVEsRUFBVyxNQUFNLGVBQWUsQ0FBQztBQUN0RSxPQUFPLEVBQUMsWUFBWSxFQUFDLE1BQU0saUJBQWlCLENBQUM7QUFDN0MsT0FBTyxFQUFDLGlCQUFpQixFQUFDLE1BQU0sc0JBQXNCLENBQUM7QUFFdkQsT0FBTyxFQUFDLFlBQVksRUFBQyxNQUFNLGlCQUFpQixDQUFDO0FBQzdDLE9BQU8sRUFBQyxnQkFBZ0IsRUFBQyxNQUFNLHNCQUFzQixDQUFDO0FBRXRELE9BQU8sRUFBQyxpQkFBaUIsRUFBQyxNQUFNLHVCQUF1QixDQUFDO0FBQ3hELE9BQU8sRUFBQyxtQ0FBbUMsRUFBRSwrQkFBK0IsRUFBQyxNQUFNLDhDQUE4QyxDQUFDO0FBQ2xJLE9BQU8sRUFBQyx1QkFBdUIsRUFBQyxNQUFNLDBDQUEwQyxDQUFDO0FBQ2pGLE9BQU8sRUFBQyxpQkFBaUIsRUFBQyxNQUFNLHVDQUF1QyxDQUFDO0FBQ3hFLE9BQU8sRUFBQyxxQkFBcUIsRUFBQyxNQUFNLDRDQUE0QyxDQUFDO0FBQ2pGLE9BQU8sRUFBQyxtQkFBbUIsRUFBRSxvQkFBb0IsRUFBQyxNQUFNLGFBQWEsQ0FBQztBQUN0RSxPQUFPLEVBQUMsa0JBQWtCLEVBQUUsV0FBVyxFQUFDLE1BQU0saUNBQWlDLENBQUM7O0FBT2hGLE1BQU0sT0FBTyxXQUFXO0lBQ3RCLE1BQU0sQ0FBQyxPQUFPLENBQ1osU0FBNEIsSUFBSSxFQUNoQyxzQkFBc0IsR0FBRyxxQkFBcUI7UUFFOUMsTUFBTSxTQUFTLEdBQWU7WUFDNUIsWUFBWTtZQUNaLGdCQUFnQjtZQUNoQixFQUFDLE9BQU8sRUFBRSxXQUFXLEVBQUUsVUFBVSxFQUFFLG1CQUFtQixFQUFDO1lBQ3ZELEVBQUMsT0FBTyxFQUFFLFlBQVksRUFBRSxVQUFVLEVBQUUsb0JBQW9CLEVBQUM7WUFDekQsRUFBQyxPQUFPLEVBQUUsaUJBQWlCLEVBQUUsUUFBUSxFQUFFLHNCQUFzQixFQUFDO1lBQzlELEVBQUMsT0FBTyxFQUFFLFdBQVcsRUFBRSxRQUFRLEVBQUUsa0JBQWtCLEVBQUM7WUFDcEQ7Z0JBQ0UsT0FBTyxFQUFFLCtCQUErQjtnQkFDeEMsUUFBUSxFQUFFLG1DQUFtQzthQUM5QztZQUNELEVBQUMsT0FBTyxFQUFFLGlCQUFpQixFQUFFLFFBQVEsRUFBRSxNQUFNLEVBQUM7WUFDOUMsRUFBQyxPQUFPLEVBQUUsZ0JBQWdCLEVBQUUsUUFBUSxFQUFFLHNCQUFzQixFQUFDO1NBQzlELENBQUM7UUFDRixJQUFJLENBQUMsTUFBTSxFQUFFLGFBQWEsRUFBRTtZQUMxQixTQUFTLENBQUMsSUFBSSxDQUFDO2dCQUNFLE9BQU8sRUFBRSxpQkFBaUI7Z0JBQzFCLFFBQVEsRUFBRSx1QkFBdUI7Z0JBQ2pDLEtBQUssRUFBRSxJQUFJO2FBQ1osQ0FBQyxDQUFDO1NBQ25CO1FBQ0QsT0FBTztZQUNMLFFBQVEsRUFBRSxXQUFXO1lBQ3JCLFNBQVMsRUFBRTtnQkFDVCxZQUFZO2dCQUNaLGdCQUFnQjtnQkFDaEIsRUFBQyxPQUFPLEVBQUUsV0FBVyxFQUFFLFVBQVUsRUFBRSxtQkFBbUIsRUFBQztnQkFDdkQsRUFBQyxPQUFPLEVBQUUsWUFBWSxFQUFFLFVBQVUsRUFBRSxvQkFBb0IsRUFBQztnQkFDekQsRUFBQyxPQUFPLEVBQUUsaUJBQWlCLEVBQUUsUUFBUSxFQUFFLHNCQUFzQixFQUFDO2dCQUM5RCxFQUFDLE9BQU8sRUFBRSxXQUFXLEVBQUUsUUFBUSxFQUFFLGtCQUFrQixFQUFDO2dCQUNwRDtvQkFDRSxPQUFPLEVBQUUsK0JBQStCO29CQUN4QyxRQUFRLEVBQUUsbUNBQW1DO2lCQUM5QztnQkFDRCxFQUFDLE9BQU8sRUFBRSxpQkFBaUIsRUFBRSxRQUFRLEVBQUUsTUFBTSxFQUFDO2dCQUU5QyxFQUFDLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxRQUFRLEVBQUUsc0JBQXNCLEVBQUM7YUFDOUQ7U0FDRixDQUFDO0lBQ0osQ0FBQzs7d0dBNUNVLFdBQVc7eUdBQVgsV0FBVyxZQUpGLFlBQVk7eUdBSXJCLFdBQVcsWUFKSCxDQUFDLFlBQVksQ0FBQzsyRkFJdEIsV0FBVztrQkFMdkIsUUFBUTttQkFBQztvQkFDRSxPQUFPLEVBQUUsQ0FBQyxZQUFZLENBQUM7b0JBQ3ZCLFlBQVksRUFBRSxFQUFFO29CQUNoQixPQUFPLEVBQUUsRUFBRTtpQkFDWiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7RGF0ZVRpbWVQcm92aWRlciwgU3lzdGVtRGF0ZVRpbWVQcm92aWRlcn0gZnJvbSAnLi9kYXRlLXRpbWUtcHJvdmlkZXInO1xuaW1wb3J0IHtPQXV0aExvZ2dlciwgT0F1dGhTdG9yYWdlfSBmcm9tICcuL3R5cGVzJztcbmltcG9ydCB7TW9kdWxlV2l0aFByb3ZpZGVycywgTmdNb2R1bGUsIFByb3ZpZGVyfSBmcm9tICdAYW5ndWxhci9jb3JlJztcbmltcG9ydCB7Q29tbW9uTW9kdWxlfSBmcm9tICdAYW5ndWxhci9jb21tb24nO1xuaW1wb3J0IHtIVFRQX0lOVEVSQ0VQVE9SU30gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xuXG5pbXBvcnQge09BdXRoU2VydmljZX0gZnJvbSAnLi9vYXV0aC1zZXJ2aWNlJztcbmltcG9ydCB7VXJsSGVscGVyU2VydmljZX0gZnJvbSAnLi91cmwtaGVscGVyLnNlcnZpY2UnO1xuXG5pbXBvcnQge09BdXRoTW9kdWxlQ29uZmlnfSBmcm9tICcuL29hdXRoLW1vZHVsZS5jb25maWcnO1xuaW1wb3J0IHtPQXV0aE5vb3BSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlciwgT0F1dGhSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlcn0gZnJvbSAnLi9pbnRlcmNlcHRvcnMvcmVzb3VyY2Utc2VydmVyLWVycm9yLWhhbmRsZXInO1xuaW1wb3J0IHtEZWZhdWx0T0F1dGhJbnRlcmNlcHRvcn0gZnJvbSAnLi9pbnRlcmNlcHRvcnMvZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvcic7XG5pbXBvcnQge1ZhbGlkYXRpb25IYW5kbGVyfSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vdmFsaWRhdGlvbi1oYW5kbGVyJztcbmltcG9ydCB7TnVsbFZhbGlkYXRpb25IYW5kbGVyfSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vbnVsbC12YWxpZGF0aW9uLWhhbmRsZXInO1xuaW1wb3J0IHtjcmVhdGVEZWZhdWx0TG9nZ2VyLCBjcmVhdGVEZWZhdWx0U3RvcmFnZX0gZnJvbSAnLi9mYWN0b3JpZXMnO1xuaW1wb3J0IHtEZWZhdWx0SGFzaEhhbmRsZXIsIEhhc2hIYW5kbGVyfSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vaGFzaC1oYW5kbGVyJztcblxuQE5nTW9kdWxlKHtcbiAgICAgICAgICAgIGltcG9ydHM6IFtDb21tb25Nb2R1bGVdLFxuICAgICAgICAgICAgZGVjbGFyYXRpb25zOiBbXSxcbiAgICAgICAgICAgIGV4cG9ydHM6IFtdLFxuICAgICAgICAgIH0pXG5leHBvcnQgY2xhc3MgT0F1dGhNb2R1bGUge1xuICBzdGF0aWMgZm9yUm9vdChcbiAgICBjb25maWc6IE9BdXRoTW9kdWxlQ29uZmlnID0gbnVsbCxcbiAgICB2YWxpZGF0aW9uSGFuZGxlckNsYXNzID0gTnVsbFZhbGlkYXRpb25IYW5kbGVyXG4gICk6IE1vZHVsZVdpdGhQcm92aWRlcnM8T0F1dGhNb2R1bGU+IHtcbiAgICBjb25zdCBwcm92aWRlcnM6IFByb3ZpZGVyW10gPSBbXG4gICAgICBPQXV0aFNlcnZpY2UsXG4gICAgICBVcmxIZWxwZXJTZXJ2aWNlLFxuICAgICAge3Byb3ZpZGU6IE9BdXRoTG9nZ2VyLCB1c2VGYWN0b3J5OiBjcmVhdGVEZWZhdWx0TG9nZ2VyfSxcbiAgICAgIHtwcm92aWRlOiBPQXV0aFN0b3JhZ2UsIHVzZUZhY3Rvcnk6IGNyZWF0ZURlZmF1bHRTdG9yYWdlfSxcbiAgICAgIHtwcm92aWRlOiBWYWxpZGF0aW9uSGFuZGxlciwgdXNlQ2xhc3M6IHZhbGlkYXRpb25IYW5kbGVyQ2xhc3N9LFxuICAgICAge3Byb3ZpZGU6IEhhc2hIYW5kbGVyLCB1c2VDbGFzczogRGVmYXVsdEhhc2hIYW5kbGVyfSxcbiAgICAgIHtcbiAgICAgICAgcHJvdmlkZTogT0F1dGhSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlcixcbiAgICAgICAgdXNlQ2xhc3M6IE9BdXRoTm9vcFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyLFxuICAgICAgfSxcbiAgICAgIHtwcm92aWRlOiBPQXV0aE1vZHVsZUNvbmZpZywgdXNlVmFsdWU6IGNvbmZpZ30sXG4gICAgICB7cHJvdmlkZTogRGF0ZVRpbWVQcm92aWRlciwgdXNlQ2xhc3M6IFN5c3RlbURhdGVUaW1lUHJvdmlkZXJ9LFxuICAgIF07XG4gICAgaWYgKCFjb25maWc/Lm5vSW50ZXJjZXB0b3IpIHtcbiAgICAgIHByb3ZpZGVycy5wdXNoKHtcbiAgICAgICAgICAgICAgICAgICAgICAgcHJvdmlkZTogSFRUUF9JTlRFUkNFUFRPUlMsXG4gICAgICAgICAgICAgICAgICAgICAgIHVzZUNsYXNzOiBEZWZhdWx0T0F1dGhJbnRlcmNlcHRvcixcbiAgICAgICAgICAgICAgICAgICAgICAgbXVsdGk6IHRydWUsXG4gICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICB9XG4gICAgcmV0dXJuIHtcbiAgICAgIG5nTW9kdWxlOiBPQXV0aE1vZHVsZSxcbiAgICAgIHByb3ZpZGVyczogW1xuICAgICAgICBPQXV0aFNlcnZpY2UsXG4gICAgICAgIFVybEhlbHBlclNlcnZpY2UsXG4gICAgICAgIHtwcm92aWRlOiBPQXV0aExvZ2dlciwgdXNlRmFjdG9yeTogY3JlYXRlRGVmYXVsdExvZ2dlcn0sXG4gICAgICAgIHtwcm92aWRlOiBPQXV0aFN0b3JhZ2UsIHVzZUZhY3Rvcnk6IGNyZWF0ZURlZmF1bHRTdG9yYWdlfSxcbiAgICAgICAge3Byb3ZpZGU6IFZhbGlkYXRpb25IYW5kbGVyLCB1c2VDbGFzczogdmFsaWRhdGlvbkhhbmRsZXJDbGFzc30sXG4gICAgICAgIHtwcm92aWRlOiBIYXNoSGFuZGxlciwgdXNlQ2xhc3M6IERlZmF1bHRIYXNoSGFuZGxlcn0sXG4gICAgICAgIHtcbiAgICAgICAgICBwcm92aWRlOiBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyLFxuICAgICAgICAgIHVzZUNsYXNzOiBPQXV0aE5vb3BSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlcixcbiAgICAgICAgfSxcbiAgICAgICAge3Byb3ZpZGU6IE9BdXRoTW9kdWxlQ29uZmlnLCB1c2VWYWx1ZTogY29uZmlnfSxcblxuICAgICAgICB7cHJvdmlkZTogRGF0ZVRpbWVQcm92aWRlciwgdXNlQ2xhc3M6IFN5c3RlbURhdGVUaW1lUHJvdmlkZXJ9LFxuICAgICAgXSxcbiAgICB9O1xuICB9XG59XG4iXX0=