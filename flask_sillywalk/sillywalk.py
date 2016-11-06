import inspect
import json
import flask

from collections import defaultdict
from flask_sillywalk.compat import urlparse


__SWAGGERVERSION__ = "1.3"
SUPPORTED_FORMATS = ["json"]


class SwaggerRegistryError(Exception):
    """A Swagger registry error"""
    pass


class SwaggerApiRegistry(object):
    """
    If you're going to make your Python/Flask API swagger compliant, you'll need
    to initialize a SwaggerApiRegistry with a Flask app and a baseurl.

    >>> my_app = Flask(__name__)
    >>> registry = SwaggerApiRegistry(my_app, "http://my_url.com/api/v1")

    Then you can register URLs with this class' "register" method.
    """

    def __init__(self, app=None, baseurl="http://localhost/",
                 api_version="1.0", api_descriptions={}):
        self.baseurl = baseurl
        self.api_version = api_version
        self.api_descriptions = api_descriptions
        self.basepath = urlparse(self.baseurl).path
        self.r = defaultdict(dict)
        self.models = defaultdict(dict)
        self.authorizations = defaultdict(dict)
        self.registered_routes = []
        if app is not None:
            self.app = app
            self.init_app(self.app)

    def init_app(self, app):
        """
        Initialize the Flask app by adding the base "resources" URL. Currently only JSON
        is supported, so this will add the URL <baseurl>/resources.json to your app.
        """
        for fmt in SUPPORTED_FORMATS:
            app.add_url_rule(
                "{0}/resources.{1}".format(
                    self.basepath.rstrip("/"),
                    fmt),
                "resources",
                self.jsonify(self.resources))

    def jsonify(self, f):
        """
        In case we need to serialize different stuff in the future.
        """

        def inner_func():
            return flask.Response(response=json.dumps(f()),
                    status=200,
                    mimetype="application/json")

        return inner_func

    def resources(self):
        """
        Gets all currently known API resources and serializes them.
        """
        resources = {
            "apiVersion": self.api_version,
            "swaggerVersion": __SWAGGERVERSION__,
            "basePath": self.baseurl,
            "models": dict(),
            "apis": list(),
            "authorizations": dict(),
        }

        for resource in self.r.keys():
            description = (self.api_descriptions[resource]
                           if resource in self.api_descriptions else "")
            resources["apis"].append({
                "path": "/" + resource + ".{format}",
                "description": description})

        for k, v in self.authorizations.items():
            resources["authorizations"][k] = v.document()

        return resources

    def registerModel(self):
        """
        Registers a Swagger Model (object).
        """

        def inner_func(c, *args, **kwargs):
            self.models[c.__name__] = c
            return c

        return inner_func

    def registerApiKeyAuthorization(self, auth):
        self.authorizations[auth.name] = auth

    def _register(self,
                  path,
                  f,
                  method,
                  content_type,
                  parameters,
                  responseMessages,
                  nickname,
                  notes,
                  auth,
                  bp):

        if self.app is None:
            raise SwaggerRegistryError(
                "You need to initialize {0} with a Flask app".format(
                    self.__class__.__name__))

        # use basepath if not set by user
        if self.basepath not in path:
            path = self.basepath + "/" + path
            path = path.replace("//", "/")

        # register views on blueprints
        app = self.app

        if bp:
            app = bp

        app.add_url_rule(
            path,
            f.__name__,
            f,
            methods=[method])

        api = Api(
            method=f,
            path=path.replace(self.basepath, ""),
            httpMethod=method,
            params=parameters,
            responseMessages=responseMessages,
            nickname=nickname,
            notes=notes,
            auth=auth)

        if api.resource not in self.app.view_functions:
            for fmt in SUPPORTED_FORMATS:
                route = "{0}/{1}.{2}".format(self.basepath.rstrip("/"),
                                             api.resource, fmt)
                if route not in self.registered_routes:
                    self.registered_routes.append(route)
                    self.app.add_url_rule(
                        route,
                        api.resource,
                        self.jsonify(self.show_resource(api.resource)))

        if self.r[api.resource].get(api.path) is None:
            self.r[api.resource][api.path] = list()
        self.r[api.resource][api.path].append(api)

    def add_register(self,
                     path,
                     f,
                     method="GET",
                     content_type="application/json",
                     parameters=[],
                     responseMessages=[],
                     nickname=None,
                     notes=None,
                     auth=None,
                     bp=None):
        """
        Registers an API endpoint.

        Usage:

        >>> def get_cheese(cheesename):
        >>>     # some function
        >>> my_registry.add_register(
        ...     "/api/v1/cheese/<cheeseName>",
        ...     get_cheese,
        ...     parameters=[ApiParameter(
        ...         name="cheeseName",
        ...         description="The name of the cheese to fetch",
        ...         required=True,
        ...         dataType="str",
        ...         paramType="path",
        ...         allowMultiple=False)],
        ...     notes='For getting cheese, you know...',
        ...     responseMessages=[
        ...         ApiErrorResponse(400, "Sorry, we're fresh out of that cheese."),
        ...         ApiErrorResponse(418, "I'm actually a teapot")]))

        """
        self._register(path, f, method, content_type, parameters,
                       responseMessages, nickname, notes, auth, bp)

    def register(self,
                 path,
                 method="GET",
                 content_type="application/json",
                 parameters=[],
                 responseMessages=[],
                 nickname=None,
                 notes=None,
                 auth=None,
                 bp=None):
        """
        Registers an API endpoint.

        Usage:

        >>> @my_registry.register(
        ...     "/api/v1/cheese/<cheeseName>",
        ...     parameters=[ApiParameter(
        ...         name="cheeseName",
        ...         description="The name of the cheese to fetch",
        ...         required=True,
        ...         dataType="str",
        ...         paramType="path",
        ...         allowMultiple=False)],
        ...     notes='For getting cheese, you know...',
        ...     responseMessages=[
        ...         ApiErrorResponse(400, "Sorry, we're fresh out of that cheese."),
        ...         ApiErrorResponse(418, "I'm actually a teapot")]))
        >>> def get_cheese(cheesename):
        >>>     # some function

        """
        def inner_func(f):
            self._register(path, f, method, content_type, parameters,
                           responseMessages, nickname, notes, auth, bp)
        return inner_func

    def show_resource(self, resource):
        """
        Serialize a single resource.
        """

        def inner_func():
            return_value = {
                "resourcePath": resource.rstrip("/"),
                "apiVersion": self.api_version,
                "swaggerVersion": __SWAGGERVERSION__,
                "basePath": self.baseurl,
                "apis": list(),
                "models": dict()
            }
            models = set()
            resource_map = self.r.get(resource)
            for path, apis in resource_map.items():
                api_object = {
                    "path": path,
                    "description": "",
                    "operations": list()}
                for api in apis:
                    api_object["operations"].append(api.document())
                    for m in api.responseMessages:
                        mname = getattr(m, "responseModel", None)
                        if mname is None or mname not in self.models \
                                or mname in models:
                            continue

                        models.add(mname)
                        model = self.models[mname]
                        models = models | model.dependencies()

                return_value["apis"].append(api_object)

            for mname in models:
                if mname in return_value["models"]:
                    continue
                if mname not in self.models:
                    continue

                model = self.models[mname]
                return_value["models"][mname] = model.document()

            return return_value

        return inner_func

# A schema property. Typically subclasses of this type will be used
# in a subclass of ApimodelParent.
#
# NB: No docitem here since it could accidentally end up in the
# generated schema.
class ApiModelItem(object):
    type = None
    format = None
    ref = None
    default = None
    enum = None
    items = None
    unique = False
    minimum = None
    maximum = None

    required = True

    @classmethod
    def document(cls):
        r = {
            "description": "" if cls.__doc__ is None else cls.__doc__,
        }

        if cls.type is not None:
            r['type'] = str(cls.type)
            if cls.format is not None:
                r["format"] = str(cls.format)
        elif cls.ref is not None:
            if inspect.isclass(cls.ref):
                r["$ref"] = cls.ref.__name__
            else:
                r["$ref"] = str(cls.ref)

        if cls.default is not None:
            r["defaultValue"] = cls.default

        if cls.enum is not None:
            r["enum"] = list(cls.enum)

        if cls.minimum is not None:
            r["minimum"] = str(cls.minimum)

        if cls.maximum is not None:
            r["maximum"] = str(cls.maximum)

        if cls.items is not None:
            r["items"] = {}
            if inspect.isclass(cls.items):
                r["items"]["type"] = cls.items.__name__
            else:
                r["items"]["type"] = str(cls.items)

        if cls.type == "list" and cls.unique:
            r["uniqueItems"] = True

        return r

    @classmethod
    def dependencies(cls):
        models = set()

        if cls.items is not None:
            if not isinstance(cls.items, str):
                models.add(cls.items.__name__)
                models = models | cls.items.dependencies()
            elif cls.items not in ("integer", "long", "float", "double", \
                "string", "byte", "boolean", "date", "dateTime"):
                models.add(cls.items)

        if cls.ref is not None:
            models.add(cls.ref)

        return models


# Defines a Model schema. Typically a subclass of this would have a
# collection of subclasses of ApiModelItem, each of which represents a
# single property in the schema.
#
# NB: No docitem here since it could accidentally end up in the
# generated schema.
class ApiModelParent(object):
    @classmethod
    def document(cls):
        r = {
            "id": cls.__name__,
            "description": "" if cls.__doc__ is None else cls.__doc__ ,
            "properties": {},
            "required": [],
        }

        items = [getattr(cls, a) for a in cls.__dict__]
        items = [a for a in items if inspect.isclass(a)]
        items = [a for a in items if issubclass(a, ApiModelItem)]

        for item in items:
            name = item.__name__
            r["properties"][name] = item.document()
            if item.required:
                r["required"].append(name)

        return r

    @classmethod
    def dependencies(cls):
        models = set()

        items = [getattr(cls, a) for a in cls.__dict__]
        items = [a for a in items if inspect.isclass(a)]
        items = [a for a in items if issubclass(a, ApiModelItem)]

        for item in items:
            models = models | item.dependencies()

        return models


class SwaggerDocumentable(object):
    """
    A documentable swagger object, e.g. an API endpoint,
    an API parameter, an API error response...
    """

    def document(self):
        return self.__dict__


class Api(SwaggerDocumentable):
    """
    A single API endpoint.
    """

    def __init__(
            self,
            method,
            path,
            httpMethod,
            params=None,
            responseMessages=None,
            nickname=None,
            notes=None,
            auth=None):
        self.httpMethod = httpMethod
        self.summary = method.__doc__ if method.__doc__ is not None else ""
        self.resource = path.lstrip("/").split("/")[0]
        self.path = path.replace("<", "{").replace(">", "}")
        self.parameters = [] if params is None else params
        self.responseMessages = [] if responseMessages is None else responseMessages
        self.nickname = "" if nickname is None else nickname
        self.notes = notes
        self.authorizations = [] if auth is None else auth

    # See https://github.com/wordnik/swagger-core/wiki/API-Declaration
    def document(self):
        ret = self.__dict__.copy()
        # need to serialize these guys
        ret["parameters"] = [p.document() for p in self.parameters]
        ret["responseMessages"] = [e.document() for e in self.responseMessages]
        ret["authorizations"] = dict()
        for e in self.authorizations:
            ret["authorizations"][e.name] = []
        return ret

    def __hash__(self):
        return hash(self.path)


class ApiParameter(SwaggerDocumentable):
    """
    A single API parameter
    """

    def __init__(
            self,
            name,
            description,
            required,
            dataType,
            paramType,
            allowMultiple=False):
        self.name = name
        self.description = description
        self.required = required
        self.dataType = dataType
        self.paramType = paramType
        self.allowMultiple = allowMultiple

    def document(self):
        return self.__dict__


class ImplicitApiParameter(ApiParameter):
    """
    Not sure what I was thinking here... --hobbeswalsh
    """

    def __init__(self, *args, **kwargs):
        if "default_value" not in kwargs:
            raise TypeError(
                "You need to provide an implicit param with a default value.")
        super(ImplicitApiParameter, self).__init__(*args, **kwargs)
        self.defaultValue = kwargs.get("default_value")


class ApiKeyAuthorization(SwaggerDocumentable):
    """
    An API Key authorization object.
    """

    def __init__(
            self,
            name,
            passAs="header",
            keyname=None):
        self.type = "apiKey"
        self.name = name
        self.passAs = passAs
        self.keyname = name if keyname is None else keyname

    def document(self):
        d = self.__dict__.copy()
        del d["name"]
        return d


class ApiResponse(SwaggerDocumentable):
    """
    An API response.
    """
    def __init__(self, code, message, model=None):
        self.message = message
        self.code = code
        self.responseModel = model


class ApiErrorResponse(SwaggerDocumentable):
    """
    An API error response.
    """

    def __init__(self, code, message):
        self.message = message
        self.code = code
