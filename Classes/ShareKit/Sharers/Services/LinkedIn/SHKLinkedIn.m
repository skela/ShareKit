//
//  SHKLinkedIn.m
//  ShareKit
//
//  Created by Aleksander George Slater on 13/08/10.
//  Based on SHKDelicous.m
//  Created by Nathan Weiner on 6/21/10.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//
//

#import "SHKLinkedIn.h"
#import "OAuthConsumer.h"

// You can leave this be.  The user will actually never see this url.  ShareKit just looks for
// when delicious redirects to this url and intercepts it.  It can be any url.
#define SHKLinkedInCallbackUrl		@"http://getsharekit.com/oauthcallback"


// http://github.com/jdg/oauthconsumer/blob/master/OATokenManager.m

@implementation SHKLinkedIn


- (id)init
{
	if (self = [super init])
	{		
		self.consumerKey = SHKLinkedInConsumerKey;		
		self.secretKey = SHKLinkedInSecretKey;
		self.authorizeCallbackURL = [NSURL URLWithString:@"http://linkedin_oauth/success"];
		//self.authorizeCallbackURL = [NSURL URLWithString:@"https://www.linkedin.com/uas/oauth/authorize/submit"];
		self.requestURL = [NSURL URLWithString:@"https://api.linkedin.com/uas/oauth/requestToken"];
		self.authorizeURL = [NSURL URLWithString:@"https://api.linkedin.com/uas/oauth/authorize"];
		self.accessURL = [NSURL URLWithString:@"https://api.linkedin.com/uas/oauth/accessToken"];
		
		self.signatureProvider = [[[OAHMAC_SHA1SignatureProvider alloc] init] autorelease];
	}	
	return self;
}


#pragma mark -
#pragma mark Configuration : Service Defination

+ (NSString *)sharerTitle
{
	return @"LinkedIn";
}

+ (BOOL)canShareText
{
	return YES;
}

+ (BOOL)requiresAuthentication
{
	return YES;
}

#pragma mark -
#pragma mark Authorization (Token Request)

- (void)tokenRequest
{
	[[SHKActivityIndicator currentIndicator] displayActivity:SHKLocalizedString(@"Connecting...")];
	
    OAMutableURLRequest *oRequest = [[OAMutableURLRequest alloc] initWithURL:requestURL
																	consumer:consumer
																	   token:nil   // we don't have a Token yet
																	   realm:nil
														   signatureProvider:signatureProvider];

	

	
	[oRequest setHTTPMethod:@"POST"];
	
	[self tokenRequestModifyRequest:oRequest];
	
    OAAsynchronousDataFetcher *fetcher = [OAAsynchronousDataFetcher asynchronousFetcherWithRequest:oRequest
																						  delegate:self
																				 didFinishSelector:@selector(tokenRequestTicket:didFinishWithData:)
																				   didFailSelector:@selector(tokenRequestTicket:didFailWithError:)];
	[fetcher start];	
	[oRequest release];
}

- (BOOL)isAuthorized
{		
	return [self restoreAccessToken];
}

- (void)promptAuthorization
{		
	[super promptAuthorization]; // OAuth process		
}

- (void)tokenRequestModifyRequest:(OAMutableURLRequest *)oRequest
{
	
}

- (void)tokenRequestTicket:(OAServiceTicket *)ticket didFinishWithData:(NSData *)data 
{
	if (SHKDebugShowLogs) // check so we don't have to alloc the string with the data if we aren't logging
		SHKLog(@"tokenRequestTicket Response Body: %@", [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease]);
	
	NSLog(@"Token request response body %@",[[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease]);
	[[SHKActivityIndicator currentIndicator] hide];
	
	if (ticket.didSucceed) 
	{
		NSString *responseBody = [[NSString alloc] initWithData:data
													   encoding:NSUTF8StringEncoding];
		self.requestToken = [[OAToken alloc] initWithHTTPResponseBody:responseBody];
		[responseBody release];
		
		[self tokenAuthorize];
	}
	
	else
		// TODO - better error handling here
		[self tokenRequestTicket:ticket didFailWithError:[SHK error:SHKLocalizedString(@"There was a problem requesting authorization from %@"), [self sharerTitle]]];
}

- (void)tokenRequestTicket:(OAServiceTicket *)ticket didFailWithError:(NSError*)error
{
	[[SHKActivityIndicator currentIndicator] hide];
	
	[[[[UIAlertView alloc] initWithTitle:SHKLocalizedString(@"Request Error")
								 message:error!=nil?[error localizedDescription]:SHKLocalizedString(@"There was an error while sharing")
								delegate:nil
					   cancelButtonTitle:SHKLocalizedString(@"Close")
					   otherButtonTitles:nil] autorelease] show];
}

#pragma mark -
#pragma mark Authorization (Token Authorise)

- (void)tokenAuthorize
{	
	NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"%@?oauth_token=%@", authorizeURL.absoluteString, requestToken.key]];
	
	SHKOAuthView *auth = [[SHKOAuthView alloc] initWithURL:url delegate:self];
	auth.title = @"LinkedIn";
	[[SHK currentHelper] showViewController:auth];	
	[auth release];
}

- (void)tokenAuthorizeView:(SHKOAuthView *)authView didFinishWithSuccess:(BOOL)success queryParams:(NSMutableDictionary *)queryParams error:(NSError *)error;
{
	[[SHK currentHelper] hideCurrentViewControllerAnimated:YES];
	
	if (!success)
	{
		[[[[UIAlertView alloc] initWithTitle:SHKLocalizedString(@"Authorize Error")
									 message:error!=nil?[error localizedDescription]:SHKLocalizedString(@"There was an error while authorizing")
									delegate:nil
						   cancelButtonTitle:SHKLocalizedString(@"Close")
						   otherButtonTitles:nil] autorelease] show];
	}	
	
	else 
	{
		self.authorizeResponseQueryVars = queryParams;
		
		[self tokenAccess];
	}
}

- (void)tokenAuthorizeCancelledView:(SHKOAuthView *)authView
{
	[[SHK currentHelper] hideCurrentViewControllerAnimated:YES];	
}


- (BOOL)handleResponse:(SHKRequest *)aRequest
{
	NSString *response = [aRequest getResult];
	
	if ([response isEqualToString:@"401 Forbidden"])
	{
		[self sendDidFailShouldRelogin];		
		return NO;		
	} 
	
	return YES;
}


#pragma mark -
#pragma mark Token Access

- (void)tokenAccess:(BOOL)refresh
{
	if (!refresh)
		[[SHKActivityIndicator currentIndicator] displayActivity:SHKLocalizedString(@"Authenticating...")];
	
    OAMutableURLRequest *oRequest = [[OAMutableURLRequest alloc] initWithURL:accessURL
																	consumer:consumer
																	   token:(refresh ? accessToken : requestToken)
																	   realm:nil   // our service provider doesn't specify a realm
														   signatureProvider:signatureProvider]; // use the default method, HMAC-SHA1
	
    [oRequest setHTTPMethod:@"GET"];
	
	[self tokenAccessModifyRequest:oRequest];
	
    OAAsynchronousDataFetcher *fetcher = [OAAsynchronousDataFetcher asynchronousFetcherWithRequest:oRequest
																						  delegate:self
																				 didFinishSelector:@selector(tokenAccessTicket:didFinishWithData:)
																				   didFailSelector:@selector(tokenAccessTicket:didFailWithError:)];
	[fetcher start];
	[oRequest release];
}

- (void)tokenAccessModifyRequest:(OAMutableURLRequest *)oRequest
{
	if (pendingAction == SHKPendingRefreshToken)
	{
		if (accessToken.sessionHandle != nil)
			[oRequest setOAuthParameterName:@"oauth_session_handle" withValue:accessToken.sessionHandle];	
	}
	
	else
		[oRequest setOAuthParameterName:@"oauth_verifier" withValue:[authorizeResponseQueryVars objectForKey:@"oauth_verifier"]];	
}

- (void)tokenAccessTicket:(OAServiceTicket *)ticket didFinishWithData:(NSData *)data 
{
	if (SHKDebugShowLogs) // check so we don't have to alloc the string with the data if we aren't logging
		SHKLog(@"tokenAccessTicket Response Body: %@", [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease]);
	
	NSLog(@"tokenaccessticket response body: %@",[[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease]);
	
	[[SHKActivityIndicator currentIndicator] hide];
	
	if (ticket.didSucceed) 
	{
		NSString *responseBody = [[NSString alloc] initWithData:data
													   encoding:NSUTF8StringEncoding];
		self.accessToken = [[OAToken alloc] initWithHTTPResponseBody:responseBody];
		[responseBody release];
		
		[self storeAccessToken];
		
		[self tryPendingAction];
	}
	
	
	else
		// TODO - better error handling here
		[self tokenAccessTicket:ticket didFailWithError:[SHK error:SHKLocalizedString(@"There was a problem requesting access from %@", [self sharerTitle])]];
}

#pragma mark -
#pragma mark Share Form

- (NSArray *)shareFormFieldsForType:(SHKShareType)type
{
	if (type == SHKShareTypeURL)
		return [NSArray arrayWithObjects:
				[SHKFormFieldSettings label:SHKLocalizedString(@"Title") key:@"title" type:SHKFormFieldTypeText start:item.title],
				[SHKFormFieldSettings label:SHKLocalizedString(@"Tags") key:@"tags" type:SHKFormFieldTypeText start:item.tags],
				[SHKFormFieldSettings label:SHKLocalizedString(@"Notes") key:@"text" type:SHKFormFieldTypeText start:item.text],
				[SHKFormFieldSettings label:SHKLocalizedString(@"Shared") key:@"shared" type:SHKFormFieldTypeSwitch start:SHKFormFieldSwitchOff],
				nil];
	
	return nil;
}



#pragma mark -
#pragma mark Share API Methods

- (BOOL)send
{	
	if ([self validateItem])
	{			
		OAMutableURLRequest *oRequest = [[OAMutableURLRequest alloc] initWithURL:[NSURL URLWithString:@"http://api.linkedin.com/v1/people/~/current-status"]
																		consumer:consumer
																		   token:accessToken
																		   realm:@"api.linkedin.com"
															   signatureProvider:nil];
		
		[oRequest setHTTPMethod:@"PUT"];
		
		NSString *httpBody = [NSString stringWithFormat:@"<?xml version=\"1.0\" encoding=\"UTF-8\"?><current-status>%@</current-status>",item.text];
		//NSString *httpBody = [NSString stringWithFormat:@"<?xml version=\"1.0\" encoding=\"UTF-8\"?><current-status>%@</current-status>",@"testing 123"];
		[oRequest setHTTPBody:[httpBody dataUsingEncoding:NSUTF8StringEncoding]];
		
		OAAsynchronousDataFetcher *fetcher = [OAAsynchronousDataFetcher asynchronousFetcherWithRequest:oRequest
							 delegate:self
					didFinishSelector:@selector(sendTicket:didFinishWithData:)
					  didFailSelector:@selector(sendTicket:didFailWithError:)];	
		
		[fetcher start];
		[oRequest release];
		
		// Notify delegate
		[self sendDidStart];
		
		return YES;
	}
	
	return NO;
}


- (void)sendTicket:(OAServiceTicket *)ticket didFinishWithData:(NSData *)data 
{		
	if (ticket.didSucceed && [ticket.body rangeOfString:@"\"done\""].location != NSNotFound) 
	{
		// Do anything?
	}
	
	else 
	{	
		if (SHKDebugShowLogs) // check so we don't have to alloc the string with the data if we aren't logging
			SHKLog(@"SHKLinkedIn sendTicket Response Body: %@", [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease]);

		// Look for oauth problems		
		// TODO - I'd prefer to use regex for this but that would require OS4 or adding a regex library
		NSError *error;
		NSString *body = [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease];
		NSLog(@"status update response: %@",body);
		
		// Expired token
		if ([body rangeOfString:@"token_expired"].location != NSNotFound)
		{
			[self refreshToken];				
			return;
		}
		else if ([body rangeOfString:@"Can not set member current status because number of status text exceeds the limit"].location != NSNotFound)
			error = [SHK error:SHKLocalizedString(@"The LinkedIn status update failed because the message was too long.")];
		else
			error = [SHK error:SHKLocalizedString(@"There was a problem saving to LinkedIn.")];
		
		[self sendTicket:ticket didFailWithError:error];
	}
	
	// Notify delegate
	[self sendDidFinish];
}

- (void)sendTicket:(OAServiceTicket *)ticket didFailWithError:(NSError*)error
{
	[self sendDidFailWithError:error];
}



@end
