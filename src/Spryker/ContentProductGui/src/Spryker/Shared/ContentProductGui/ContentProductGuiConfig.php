<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\ContentProductGui;

use Spryker\Shared\Kernel\AbstractSharedConfig;

class ContentProductGuiConfig extends AbstractSharedConfig
{
    /**
     * @uses \Spryker\Shared\ContentProduct\ContentProductConfig::CONTENT_TYPE_PRODUCT_ABSTRACT_LIST
     *
     * Content item abstract product list
     */
    public const CONTENT_TYPE_PRODUCT_ABSTRACT_LIST = 'Abstract Product List';

    /**
     * @uses \Spryker\Shared\ContentProduct\ContentProductConfig::CONTENT_TERM_PRODUCT_ABSTRACT_LIST
     *
     * Content item abstract product list
     */
    public const CONTENT_TERM_PRODUCT_ABSTRACT_LIST = 'Abstract Product List';

    /**
     * @uses \Spryker\Shared\ContentProduct\ContentProductConfig::TWIG_FUNCTION_NAME
     */
    protected const TWIG_FUNCTION_NAME = 'content_product_abstract_list';

    /**
     * @uses \Spryker\Shared\ContentProduct\ContentProductConfig::WIDGET_TEMPLATE_IDENTIFIER_DEFAULT
     */
    protected const WIDGET_TEMPLATE_IDENTIFIER_DEFAULT = 'default';

    /**
     * @uses \Spryker\Shared\ContentProduct\ContentProductConfig::WIDGET_TEMPLATE_DISPLAY_NAME_DEFAULT
     */
    protected const WIDGET_TEMPLATE_DISPLAY_NAME_DEFAULT = 'content_product_abstract_list.template.default';

    /**
     * @uses \Spryker\Shared\ContentProduct\ContentProductConfig::WIDGET_TEMPLATE_IDENTIFIER_TOP_TITLE
     */
    protected const WIDGET_TEMPLATE_IDENTIFIER_TOP_TITLE = 'top-title';

    /**
     * @uses \Spryker\Shared\ContentProduct\ContentProductConfig::WIDGET_TEMPLATE_DISPLAY_NAME_TOP_TITLE
     */
    protected const WIDGET_TEMPLATE_DISPLAY_NAME_TOP_TITLE = 'content_product_abstract_list.template.top-title';

    /**
     * @return array
     */
    public function getContentWidgetTemplates(): array
    {
        return [
            static::WIDGET_TEMPLATE_IDENTIFIER_DEFAULT => static::WIDGET_TEMPLATE_DISPLAY_NAME_DEFAULT,
            static::WIDGET_TEMPLATE_IDENTIFIER_TOP_TITLE => static::WIDGET_TEMPLATE_DISPLAY_NAME_TOP_TITLE,
        ];
    }

    /**
     * @return string
     */
    public function getTwigFunctionName(): string
    {
        return static::TWIG_FUNCTION_NAME;
    }
}
