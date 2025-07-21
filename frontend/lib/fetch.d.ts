export type Problem = {
    pointer: string | null;
    detail: string | null;
};
export type ServerResponse<T> = {
    status: "ok";
    body: T;
} | {
    status: "clientError";
    problems: Problem[];
} | {
    status: "serverError";
} | {
    status: "unauthorized";
} | never;
export type LogoutConfig = {
    endpoint: string;
    redirect: string;
};
export type Header = [string, string];
export declare const TOKEN_KEY = "token";
export declare class FetchBuilder {
    #private;
    constructor(method: "GET" | "POST" | "PUT" | "DELETE", url: string);
    setBody(body: object | null): FetchBuilder;
    setHeaders(headers: Header[] | null): FetchBuilder;
    setLogout(logoutConfig: LogoutConfig | null): FetchBuilder;
    fetch<T>(): Promise<ServerResponse<T>>;
}
export declare function fetch<T>(method: "GET" | "POST" | "PUT" | "DELETE", url: string, additionalHeaders: Header[] | null, body: object | null, logoutConfig: LogoutConfig | null): Promise<ServerResponse<T>>;
export declare function logout(endpoint: string, additionalHeaders: Header[] | null, redirect: string): Promise<never>;
