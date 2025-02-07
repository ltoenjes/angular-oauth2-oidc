import { Injectable, Optional } from '@angular/core';
import { of, merge } from 'rxjs';
import { catchError, filter, map, take, mergeMap, timeout, } from 'rxjs/operators';
import * as i0 from "@angular/core";
import * as i1 from "../oauth-service";
import * as i2 from "./resource-server-error-handler";
import * as i3 from "../oauth-module.config";
export class DefaultOAuthInterceptor {
    constructor(oAuthService, errorHandler, moduleConfig) {
        this.oAuthService = oAuthService;
        this.errorHandler = errorHandler;
        this.moduleConfig = moduleConfig;
    }
    checkUrl(url) {
        if (this.moduleConfig.resourceServer.customUrlValidation) {
            return this.moduleConfig.resourceServer.customUrlValidation(url);
        }
        if (this.moduleConfig.resourceServer.allowedUrls) {
            return !!this.moduleConfig.resourceServer.allowedUrls.find((u) => url.toLowerCase().startsWith(u.toLowerCase()));
        }
        return true;
    }
    intercept(req, next) {
        const url = req.url.toLowerCase();
        if (!this.moduleConfig ||
            !this.moduleConfig.resourceServer ||
            !this.checkUrl(url)) {
            return next.handle(req);
        }
        const sendAccessToken = this.moduleConfig.resourceServer.sendAccessToken;
        if (!sendAccessToken) {
            return next
                .handle(req)
                .pipe(catchError((err) => this.errorHandler.handleError(err)));
        }
        return merge(of(this.oAuthService.getAccessToken()).pipe(filter((token) => !!token)), this.oAuthService.events.pipe(filter((e) => e.type === 'token_received'), timeout(this.oAuthService.waitForTokenInMsec || 0), catchError((_) => of(null)), // timeout is not an error
        map((_) => this.oAuthService.getAccessToken()))).pipe(take(1), mergeMap((token) => {
            if (token) {
                const header = 'Bearer ' + token;
                const headers = req.headers.set('Authorization', header);
                req = req.clone({ headers });
            }
            return next
                .handle(req)
                .pipe(catchError((err) => this.errorHandler.handleError(err)));
        }));
    }
}
DefaultOAuthInterceptor.ɵfac = i0.ɵɵngDeclareFactory({ minVersion: "12.0.0", version: "13.0.1", ngImport: i0, type: DefaultOAuthInterceptor, deps: [{ token: i1.OAuthService }, { token: i2.OAuthResourceServerErrorHandler }, { token: i3.OAuthModuleConfig, optional: true }], target: i0.ɵɵFactoryTarget.Injectable });
DefaultOAuthInterceptor.ɵprov = i0.ɵɵngDeclareInjectable({ minVersion: "12.0.0", version: "13.0.1", ngImport: i0, type: DefaultOAuthInterceptor });
i0.ɵɵngDeclareClassMetadata({ minVersion: "12.0.0", version: "13.0.1", ngImport: i0, type: DefaultOAuthInterceptor, decorators: [{
            type: Injectable
        }], ctorParameters: function () { return [{ type: i1.OAuthService }, { type: i2.OAuthResourceServerErrorHandler }, { type: i3.OAuthModuleConfig, decorators: [{
                    type: Optional
                }] }]; } });
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiZGVmYXVsdC1vYXV0aC5pbnRlcmNlcHRvci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3Byb2plY3RzL2xpYi9zcmMvaW50ZXJjZXB0b3JzL2RlZmF1bHQtb2F1dGguaW50ZXJjZXB0b3IudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsT0FBTyxFQUFFLFVBQVUsRUFBRSxRQUFRLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFRckQsT0FBTyxFQUFjLEVBQUUsRUFBRSxLQUFLLEVBQUUsTUFBTSxNQUFNLENBQUM7QUFDN0MsT0FBTyxFQUNMLFVBQVUsRUFDVixNQUFNLEVBQ04sR0FBRyxFQUNILElBQUksRUFDSixRQUFRLEVBQ1IsT0FBTyxHQUNSLE1BQU0sZ0JBQWdCLENBQUM7Ozs7O0FBTXhCLE1BQU0sT0FBTyx1QkFBdUI7SUFDbEMsWUFDVSxZQUEwQixFQUMxQixZQUE2QyxFQUNqQyxZQUErQjtRQUYzQyxpQkFBWSxHQUFaLFlBQVksQ0FBYztRQUMxQixpQkFBWSxHQUFaLFlBQVksQ0FBaUM7UUFDakMsaUJBQVksR0FBWixZQUFZLENBQW1CO0lBQ2xELENBQUM7SUFFSSxRQUFRLENBQUMsR0FBVztRQUMxQixJQUFJLElBQUksQ0FBQyxZQUFZLENBQUMsY0FBYyxDQUFDLG1CQUFtQixFQUFFO1lBQ3hELE9BQU8sSUFBSSxDQUFDLFlBQVksQ0FBQyxjQUFjLENBQUMsbUJBQW1CLENBQUMsR0FBRyxDQUFDLENBQUM7U0FDbEU7UUFFRCxJQUFJLElBQUksQ0FBQyxZQUFZLENBQUMsY0FBYyxDQUFDLFdBQVcsRUFBRTtZQUNoRCxPQUFPLENBQUMsQ0FBQyxJQUFJLENBQUMsWUFBWSxDQUFDLGNBQWMsQ0FBQyxXQUFXLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FDL0QsR0FBRyxDQUFDLFdBQVcsRUFBRSxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUMsV0FBVyxFQUFFLENBQUMsQ0FDOUMsQ0FBQztTQUNIO1FBRUQsT0FBTyxJQUFJLENBQUM7SUFDZCxDQUFDO0lBRU0sU0FBUyxDQUNkLEdBQXFCLEVBQ3JCLElBQWlCO1FBRWpCLE1BQU0sR0FBRyxHQUFHLEdBQUcsQ0FBQyxHQUFHLENBQUMsV0FBVyxFQUFFLENBQUM7UUFFbEMsSUFDRSxDQUFDLElBQUksQ0FBQyxZQUFZO1lBQ2xCLENBQUMsSUFBSSxDQUFDLFlBQVksQ0FBQyxjQUFjO1lBQ2pDLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxHQUFHLENBQUMsRUFDbkI7WUFDQSxPQUFPLElBQUksQ0FBQyxNQUFNLENBQUMsR0FBRyxDQUFDLENBQUM7U0FDekI7UUFFRCxNQUFNLGVBQWUsR0FBRyxJQUFJLENBQUMsWUFBWSxDQUFDLGNBQWMsQ0FBQyxlQUFlLENBQUM7UUFFekUsSUFBSSxDQUFDLGVBQWUsRUFBRTtZQUNwQixPQUFPLElBQUk7aUJBQ1IsTUFBTSxDQUFDLEdBQUcsQ0FBQztpQkFDWCxJQUFJLENBQUMsVUFBVSxDQUFDLENBQUMsR0FBRyxFQUFFLEVBQUUsQ0FBQyxJQUFJLENBQUMsWUFBWSxDQUFDLFdBQVcsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUM7U0FDbEU7UUFFRCxPQUFPLEtBQUssQ0FDVixFQUFFLENBQUMsSUFBSSxDQUFDLFlBQVksQ0FBQyxjQUFjLEVBQUUsQ0FBQyxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxLQUFLLEVBQUUsRUFBRSxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUN2RSxJQUFJLENBQUMsWUFBWSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQzNCLE1BQU0sQ0FBQyxDQUFDLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQyxDQUFDLElBQUksS0FBSyxnQkFBZ0IsQ0FBQyxFQUMxQyxPQUFPLENBQUMsSUFBSSxDQUFDLFlBQVksQ0FBQyxrQkFBa0IsSUFBSSxDQUFDLENBQUMsRUFDbEQsVUFBVSxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxFQUFFLENBQUMsSUFBSSxDQUFDLENBQUMsRUFBRSwwQkFBMEI7UUFDdkQsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxJQUFJLENBQUMsWUFBWSxDQUFDLGNBQWMsRUFBRSxDQUFDLENBQy9DLENBQ0YsQ0FBQyxJQUFJLENBQ0osSUFBSSxDQUFDLENBQUMsQ0FBQyxFQUNQLFFBQVEsQ0FBQyxDQUFDLEtBQUssRUFBRSxFQUFFO1lBQ2pCLElBQUksS0FBSyxFQUFFO2dCQUNULE1BQU0sTUFBTSxHQUFHLFNBQVMsR0FBRyxLQUFLLENBQUM7Z0JBQ2pDLE1BQU0sT0FBTyxHQUFHLEdBQUcsQ0FBQyxPQUFPLENBQUMsR0FBRyxDQUFDLGVBQWUsRUFBRSxNQUFNLENBQUMsQ0FBQztnQkFDekQsR0FBRyxHQUFHLEdBQUcsQ0FBQyxLQUFLLENBQUMsRUFBRSxPQUFPLEVBQUUsQ0FBQyxDQUFDO2FBQzlCO1lBRUQsT0FBTyxJQUFJO2lCQUNSLE1BQU0sQ0FBQyxHQUFHLENBQUM7aUJBQ1gsSUFBSSxDQUFDLFVBQVUsQ0FBQyxDQUFDLEdBQUcsRUFBRSxFQUFFLENBQUMsSUFBSSxDQUFDLFlBQVksQ0FBQyxXQUFXLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDO1FBQ25FLENBQUMsQ0FBQyxDQUNILENBQUM7SUFDSixDQUFDOztvSEFqRVUsdUJBQXVCO3dIQUF2Qix1QkFBdUI7MkZBQXZCLHVCQUF1QjtrQkFEbkMsVUFBVTs7MEJBS04sUUFBUSIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IEluamVjdGFibGUsIE9wdGlvbmFsIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XG5cbmltcG9ydCB7XG4gIEh0dHBFdmVudCxcbiAgSHR0cEhhbmRsZXIsXG4gIEh0dHBJbnRlcmNlcHRvcixcbiAgSHR0cFJlcXVlc3QsXG59IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbi9odHRwJztcbmltcG9ydCB7IE9ic2VydmFibGUsIG9mLCBtZXJnZSB9IGZyb20gJ3J4anMnO1xuaW1wb3J0IHtcbiAgY2F0Y2hFcnJvcixcbiAgZmlsdGVyLFxuICBtYXAsXG4gIHRha2UsXG4gIG1lcmdlTWFwLFxuICB0aW1lb3V0LFxufSBmcm9tICdyeGpzL29wZXJhdG9ycyc7XG5pbXBvcnQgeyBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyIH0gZnJvbSAnLi9yZXNvdXJjZS1zZXJ2ZXItZXJyb3ItaGFuZGxlcic7XG5pbXBvcnQgeyBPQXV0aE1vZHVsZUNvbmZpZyB9IGZyb20gJy4uL29hdXRoLW1vZHVsZS5jb25maWcnO1xuaW1wb3J0IHsgT0F1dGhTZXJ2aWNlIH0gZnJvbSAnLi4vb2F1dGgtc2VydmljZSc7XG5cbkBJbmplY3RhYmxlKClcbmV4cG9ydCBjbGFzcyBEZWZhdWx0T0F1dGhJbnRlcmNlcHRvciBpbXBsZW1lbnRzIEh0dHBJbnRlcmNlcHRvciB7XG4gIGNvbnN0cnVjdG9yKFxuICAgIHByaXZhdGUgb0F1dGhTZXJ2aWNlOiBPQXV0aFNlcnZpY2UsXG4gICAgcHJpdmF0ZSBlcnJvckhhbmRsZXI6IE9BdXRoUmVzb3VyY2VTZXJ2ZXJFcnJvckhhbmRsZXIsXG4gICAgQE9wdGlvbmFsKCkgcHJpdmF0ZSBtb2R1bGVDb25maWc6IE9BdXRoTW9kdWxlQ29uZmlnXG4gICkge31cblxuICBwcml2YXRlIGNoZWNrVXJsKHVybDogc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgaWYgKHRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLmN1c3RvbVVybFZhbGlkYXRpb24pIHtcbiAgICAgIHJldHVybiB0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5jdXN0b21VcmxWYWxpZGF0aW9uKHVybCk7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLmFsbG93ZWRVcmxzKSB7XG4gICAgICByZXR1cm4gISF0aGlzLm1vZHVsZUNvbmZpZy5yZXNvdXJjZVNlcnZlci5hbGxvd2VkVXJscy5maW5kKCh1KSA9PlxuICAgICAgICB1cmwudG9Mb3dlckNhc2UoKS5zdGFydHNXaXRoKHUudG9Mb3dlckNhc2UoKSlcbiAgICAgICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRydWU7XG4gIH1cblxuICBwdWJsaWMgaW50ZXJjZXB0KFxuICAgIHJlcTogSHR0cFJlcXVlc3Q8YW55PixcbiAgICBuZXh0OiBIdHRwSGFuZGxlclxuICApOiBPYnNlcnZhYmxlPEh0dHBFdmVudDxhbnk+PiB7XG4gICAgY29uc3QgdXJsID0gcmVxLnVybC50b0xvd2VyQ2FzZSgpO1xuXG4gICAgaWYgKFxuICAgICAgIXRoaXMubW9kdWxlQ29uZmlnIHx8XG4gICAgICAhdGhpcy5tb2R1bGVDb25maWcucmVzb3VyY2VTZXJ2ZXIgfHxcbiAgICAgICF0aGlzLmNoZWNrVXJsKHVybClcbiAgICApIHtcbiAgICAgIHJldHVybiBuZXh0LmhhbmRsZShyZXEpO1xuICAgIH1cblxuICAgIGNvbnN0IHNlbmRBY2Nlc3NUb2tlbiA9IHRoaXMubW9kdWxlQ29uZmlnLnJlc291cmNlU2VydmVyLnNlbmRBY2Nlc3NUb2tlbjtcblxuICAgIGlmICghc2VuZEFjY2Vzc1Rva2VuKSB7XG4gICAgICByZXR1cm4gbmV4dFxuICAgICAgICAuaGFuZGxlKHJlcSlcbiAgICAgICAgLnBpcGUoY2F0Y2hFcnJvcigoZXJyKSA9PiB0aGlzLmVycm9ySGFuZGxlci5oYW5kbGVFcnJvcihlcnIpKSk7XG4gICAgfVxuXG4gICAgcmV0dXJuIG1lcmdlKFxuICAgICAgb2YodGhpcy5vQXV0aFNlcnZpY2UuZ2V0QWNjZXNzVG9rZW4oKSkucGlwZShmaWx0ZXIoKHRva2VuKSA9PiAhIXRva2VuKSksXG4gICAgICB0aGlzLm9BdXRoU2VydmljZS5ldmVudHMucGlwZShcbiAgICAgICAgZmlsdGVyKChlKSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpLFxuICAgICAgICB0aW1lb3V0KHRoaXMub0F1dGhTZXJ2aWNlLndhaXRGb3JUb2tlbkluTXNlYyB8fCAwKSxcbiAgICAgICAgY2F0Y2hFcnJvcigoXykgPT4gb2YobnVsbCkpLCAvLyB0aW1lb3V0IGlzIG5vdCBhbiBlcnJvclxuICAgICAgICBtYXAoKF8pID0+IHRoaXMub0F1dGhTZXJ2aWNlLmdldEFjY2Vzc1Rva2VuKCkpXG4gICAgICApXG4gICAgKS5waXBlKFxuICAgICAgdGFrZSgxKSxcbiAgICAgIG1lcmdlTWFwKCh0b2tlbikgPT4ge1xuICAgICAgICBpZiAodG9rZW4pIHtcbiAgICAgICAgICBjb25zdCBoZWFkZXIgPSAnQmVhcmVyICcgKyB0b2tlbjtcbiAgICAgICAgICBjb25zdCBoZWFkZXJzID0gcmVxLmhlYWRlcnMuc2V0KCdBdXRob3JpemF0aW9uJywgaGVhZGVyKTtcbiAgICAgICAgICByZXEgPSByZXEuY2xvbmUoeyBoZWFkZXJzIH0pO1xuICAgICAgICB9XG5cbiAgICAgICAgcmV0dXJuIG5leHRcbiAgICAgICAgICAuaGFuZGxlKHJlcSlcbiAgICAgICAgICAucGlwZShjYXRjaEVycm9yKChlcnIpID0+IHRoaXMuZXJyb3JIYW5kbGVyLmhhbmRsZUVycm9yKGVycikpKTtcbiAgICAgIH0pXG4gICAgKTtcbiAgfVxufVxuIl19